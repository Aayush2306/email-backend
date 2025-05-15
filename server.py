from flask import Flask, redirect, session, url_for
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
from db import get_conn, put_conn
from models import create_tables
from flask import request, jsonify
import requests
from openai import OpenAI
from dateutil import parser





load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",     # allows session cookies across localhost
    SESSION_COOKIE_SECURE=False        # must be False for HTTP (not HTTPS)
)

app.secret_key = os.getenv("SECRET_KEY", "supersecret")
CORS(app, supports_credentials=True, origins=[
    "https://email.replicax.tech",
    "https://app.replicax.tech",
    "http://localhost:3000"  # Optional for local dev
])

# ✅ Google OAuth using OpenID configuration
oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send',
        'access_type': 'offline',
        'prompt': 'consent'
    }
)


def refresh_access_token(user_id, refresh_token):
    import requests

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    token_url = "https://oauth2.googleapis.com/token"

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }

    response = requests.post(token_url, data=payload).json()

    if "access_token" in response:
        new_token = response["access_token"]
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE users SET access_token = %s WHERE id = %s", (new_token, user_id))
        conn.commit()
        cur.close()
        put_conn(conn)
        return new_token
    else:
        print("❌ Failed to refresh token:", response)
        return None





def ensure_refresh_token(user_record):
    """
    Checks if refresh_token exists. If not, clears session and returns 401.
    Tries session fallback if DB is missing it.
    """
    refresh_token = (
        user_record.get("refresh_token")
        if isinstance(user_record, dict)
        else user_record[-1]
    ) or session.get("refresh_token")

    if not refresh_token:
        print("⚠️ Missing refresh_token. Forcing re-login.")
        session.clear()
        return jsonify({'logout': True}), 401

    return None




@app.route('/login')
def login():
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.google.authorize_redirect(
        redirect_uri,
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'  # 🔁 Ensures refresh_token is returned
    )



@app.route('/auth/callback')
def auth_callback():
    token = oauth.google.authorize_access_token()
    print("🧪 token from Google:", token)

    userinfo_endpoint = oauth.google.server_metadata['userinfo_endpoint']
    user_info = oauth.google.get(userinfo_endpoint).json()
    print("🔍 user_info response:", user_info)

    google_id = user_info['sub']
    email = user_info['email']
    name = user_info['name']
    picture = user_info.get('picture')
    access_token = token['access_token']
    refresh_token = token.get('refresh_token')  # May be None

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE google_id = %s", (google_id,))
    user = cur.fetchone()

    if user is None:
        cur.execute("""
            INSERT INTO users (google_id, name, email, picture, access_token, refresh_token)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (google_id, name, email, picture, access_token, refresh_token))
        print("✅ New user created with refresh_token:", refresh_token)
    else:
        # Always update both if provided
        cur.execute("""
            UPDATE users SET access_token = %s, refresh_token = %s WHERE google_id = %s
        """, (access_token, refresh_token, google_id))
        print("🔁 Existing user updated.")

    conn.commit()
    cur.close()
    put_conn(conn)

    session['user'] = {
        'email': email,
        'name': name,
        'picture': picture,
        'id': google_id,
    }

    # ✅ Always store fallback refresh_token
    session['refresh_token'] = refresh_token or session.get('refresh_token')

    return redirect('https://email.replicax.tech/email')



@app.route('/force-login')
def force_login():
    session.clear()
    return redirect('/login')  # Triggers new OAuth consent



@app.route('/profile')
def profile():
    return session.get('user', {})



@app.route('/api/fetch-emails')
def fetch_emails():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    google_id = session['user']['id']
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, access_token, refresh_token, tone, preferences FROM users WHERE google_id = %s", (google_id,))
    user = cur.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # 🚨 Check for missing refresh_token and logout if needed
    redirect_response = ensure_refresh_token(user)
    if redirect_response:
        return redirect_response

    user_id, access_token, refresh_token, tone, preferences = user
    headers = { "Authorization": f"Bearer {access_token}" }

    def refresh_token_if_needed():
        if not refresh_token:
            print("❌ Cannot refresh — missing refresh_token")
            session.clear()
            return jsonify({'logout': True}), 401
        new_token = refresh_access_token(user_id, refresh_token)
        if new_token:
            headers["Authorization"] = f"Bearer {new_token}"
            return True
        else:
            print("❌ Token refresh failed — logging out")
            session.clear()
            return jsonify({'logout': True}), 401

    # Step 1: List Gmail messages
    list_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    params = { "maxResults": 20, "labelIds": ["INBOX"] }
    list_res = requests.get(list_url, headers=headers, params=params).json()

    if list_res.get("error", {}).get("code") == 401:
        result = refresh_token_if_needed()
        if isinstance(result, dict):  # JSON response with logout
            return result
        list_res = requests.get(list_url, headers=headers, params=params).json()

    messages = list_res.get("messages", [])
    saved = 0

    for msg in messages:
        msg_id = msg['id']
        msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}"
        msg_res = requests.get(msg_url, headers=headers, params={"format": "full"}).json()

        if msg_res.get("error", {}).get("code") == 401:
            result = refresh_token_if_needed()
            if isinstance(result, dict):
                return result
            msg_res = requests.get(msg_url, headers=headers, params={"format": "full"}).json()

        headers_data = msg_res.get("payload", {}).get("headers", [])
        subject = next((h["value"] for h in headers_data if h["name"] == "Subject"), "(No Subject)")
        sender = next((h["value"] for h in headers_data if h["name"] == "From"), "(Unknown)")
        date = next((h["value"] for h in headers_data if h["name"] == "Date"), None)
        received_at = parser.parse(date) if date else None

        body = extract_body(msg_res.get("payload", {})).strip()
        if len(body) > 200:
            body = body[:200] + "..."

        cur.execute("SELECT 1 FROM emails WHERE gmail_id = %s AND user_id = %s", (msg_id, user_id))
        if cur.fetchone():
            continue

        prompt = f"""
You are an AI assistant helping a user organize their inbox.
User Tone: {tone}
User Preferences: {preferences}

Email:
Subject: {subject}
From: {sender}
Body: {body}

Is this email important to the user? Respond with "Yes" or "No".
"""
        try:
            gpt_res = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=5
            )
            print("openai got called")
            response_text = gpt_res.choices[0].message.content.strip().lower()
            is_important = 'yes' in response_text
        except Exception as e:
            print("❌ OpenAI error:", e)
            is_important = False

        cur.execute("""
            INSERT INTO emails (user_id, gmail_id, sender, subject, body, is_important, received_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, msg_id, sender, subject, body, is_important, received_at))
        saved += 1

    conn.commit()
    cur.close()
    put_conn(conn)

    return jsonify({'message': f'{saved} emails fetched and saved with importance.'})





@app.route('/api/summarize-important')
def summarize_important_emails():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    google_id = session['user']['id']
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, tone, preferences FROM users WHERE google_id = %s", (google_id,))
    user = cur.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user_id, tone, preferences = user

    cur.execute("""
        SELECT subject, sender, body
        FROM emails
        WHERE user_id = %s AND is_important = TRUE
        ORDER BY received_at DESC
        LIMIT 10
    """, (user_id,))
    rows = cur.fetchall()
    cur.close()
    put_conn(conn)

    if not rows:
        return jsonify({'summary': "No important emails found."})

    messages = "\n\n".join([
        f"From: {r[1]}\nSubject: {r[0]}\n{r[2][:500]}" for r in rows
    ])

    prompt = f"""
You are an assistant that summarizes a user's most important emails in a friendly and clear way.
User tone: {tone}
User preferences: {preferences}

Summarize the following emails into key points the user should know:

{messages}

Summary:
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )
        summary = response.choices[0].message.content.strip()
    except Exception as e:
        print("❌ GPT summary error:", e)
        summary = "There was an error generating the summary."

    return jsonify({'summary': summary})


@app.route('/api/setup', methods=['POST'])
def complete_setup():
    #print("🔐 Incoming setup request. Session =", session)

    if 'user' not in session:
        print("❌ User not in session")
        return jsonify({'error': 'Not logged in'}), 401

    try:
        data = request.json
        tone = data.get('tone')
        preferences = data.get('preferences')

        print("🎯 Received tone:", tone)
        print("🧩 Received preferences:", preferences)

        # If preferences are a string instead of list, convert
        if isinstance(preferences, str):
            preferences = [preferences]

        user_id = session['user']['id']  # Google ID (sub)

        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
            UPDATE users
            SET tone = %s, preferences = %s, setup_complete = TRUE
            WHERE google_id = %s
        """, (tone, ','.join(preferences), user_id))

        conn.commit()
        cur.close()
        put_conn(conn)

        print("✅ Preferences updated successfully for user:", user_id)
        return jsonify({'message': 'Setup complete'})

    except Exception as e:
        print("❌ Exception in /api/setup:", e)
        return jsonify({'error': 'Server error', 'details': str(e)}), 500


@app.route('/api/check-setup')
def check_setup():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    google_id = session['user']['id']  # ✅ use google_id here

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT setup_complete FROM users WHERE google_id = %s", (google_id,))
    row = cur.fetchone()
    print(row)
    cur.close()
    put_conn(conn)

    if row and row[0]:
        print("ok")
        return jsonify({'setup_complete': True})
    return jsonify({'setup_complete': False})


@app.route('/api/emails')
def get_saved_emails():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    google_id = session['user']['id']

    conn = get_conn()
    cur = conn.cursor()

    # Get the internal user ID
    cur.execute("SELECT id FROM users WHERE google_id = %s", (google_id,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error': 'User not found'}), 404

    user_id = row[0]

    # Fetch email data including `id`
    cur.execute("""
        SELECT id, subject, sender, received_at, is_important
        FROM emails
        WHERE user_id = %s
        ORDER BY received_at DESC
        LIMIT 20
    """, (user_id,))

    emails = [
        {
            "id": r[0],
            "subject": r[1],
            "sender": r[2],
            "received_at": r[3].strftime("%Y-%m-%d %H:%M"),
            "important": r[4]
        }
        for r in cur.fetchall()
    ]

    cur.close()
    put_conn(conn)

    return jsonify({"emails": emails})

def extract_body(payload):
    import base64

    def decode_base64(data):
        try:
            return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
        except:
            return ""

    # Prefer plain text
    if payload.get("mimeType") == "text/plain":
        return decode_base64(payload.get("body", {}).get("data", ""))

    # Fallback to HTML
    if payload.get("mimeType") == "text/html":
        return decode_base64(payload.get("body", {}).get("data", ""))

    # Recursively search parts
    if "parts" in payload:
        for part in payload["parts"]:
            result = extract_body(part)
            if result:
                return result

    return ""



@app.route('/api/email/<int:email_id>')
def get_email_by_id(email_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT gmail_id, subject, sender, received_at, is_important, access_token, refresh_token, u.id
        FROM emails e
        JOIN users u ON e.user_id = u.id
        WHERE e.id = %s
    """, (email_id,))
    row = cur.fetchone()
    cur.close()
    put_conn(conn)

    if not row:
        return jsonify({'error': 'Email not found'}), 404

    # 🚨 Logout if refresh_token is missing
    redirect_response = ensure_refresh_token(row)
    if redirect_response:
        return redirect_response

    gmail_id, subject, sender, received_at, is_important, access_token, refresh_token, user_id = row

    # Prepare request
    msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_id}?format=full"
    headers = { "Authorization": f"Bearer {access_token}" }
    msg_res = requests.get(msg_url, headers=headers).json()

    # 🔁 Retry if token expired
    if msg_res.get("error", {}).get("code") == 401:
        print("🔁 Access token expired. Refreshing...")

        if not refresh_token:
            session.clear()
            return jsonify({'logout': True}), 401

        new_token = refresh_access_token(user_id, refresh_token)
        if not new_token:
            session.clear()
            return jsonify({'logout': True}), 401

        headers["Authorization"] = f"Bearer {new_token}"
        msg_res = requests.get(msg_url, headers=headers).json()

    body = extract_body(msg_res.get("payload", {}))

    return jsonify({
        "subject": subject,
        "sender": sender,
        "body": body,
        "received_at": received_at.strftime("%Y-%m-%d %H:%M"),
        "important": is_important
    })



@app.route('/api/generate-reply/<int:email_id>')
def generate_ai_reply(email_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT gmail_id, subject, sender, u.tone, u.access_token, u.refresh_token, u.id
        FROM emails e
        JOIN users u ON e.user_id = u.id
        WHERE e.id = %s
    """, (email_id,))
    row = cur.fetchone()
    cur.close()
    put_conn(conn)

    if not row:
        return jsonify({'error': 'Email not found'}), 404

    # 🚨 Logout if refresh_token is missing
    redirect_response = ensure_refresh_token(row)
    if redirect_response:
        return redirect_response

    gmail_id, subject, sender, tone, access_token, refresh_token, user_id = row

    # Fetch full body
    msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gmail_id}?format=full"
    headers = { "Authorization": f"Bearer {access_token}" }
    msg_res = requests.get(msg_url, headers=headers).json()

    # 🔁 Retry if token expired
    if msg_res.get("error", {}).get("code") == 401:
        print("🔁 Access token expired. Refreshing...")

        if not refresh_token:
            session.clear()
            return jsonify({'logout': True}), 401

        new_token = refresh_access_token(user_id, refresh_token)
        if not new_token:
            session.clear()
            return jsonify({'logout': True}), 401

        headers["Authorization"] = f"Bearer {new_token}"
        msg_res = requests.get(msg_url, headers=headers).json()

    body = extract_body(msg_res.get("payload", {}))
    body = body[:1000]  # truncate for GPT safety

    prompt = f"""
You are an AI assistant writing an email reply.
User prefers a {tone} tone.

Original Email:
From: {sender}
Subject: {subject}
Body: {body}

Write a short, clear, polite reply.
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600
        )
        reply_text = response.choices[0].message.content.strip()
    except Exception as e:
        print("❌ GPT reply error:", e)
        reply_text = "Sorry, could not generate a reply."

    return jsonify({"reply": reply_text})


@app.route('/api/send-reply', methods=['POST'])
def send_reply():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    data = request.json
    email_id = data.get("email_id")
    reply_body = data.get("reply")

    if not email_id or not reply_body:
        return jsonify({'error': 'Missing data'}), 400

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT gmail_id, subject, sender, u.access_token, u.refresh_token, u.id
        FROM emails e
        JOIN users u ON e.user_id = u.id
        WHERE e.id = %s
    """, (email_id,))
    row = cur.fetchone()
    cur.close()
    put_conn(conn)

    if not row:
        return jsonify({'error': 'Email not found'}), 404

    # 🚨 Logout if refresh_token is missing
    redirect_response = ensure_refresh_token(row)
    if redirect_response:
        return redirect_response

    gmail_id, subject, to_email, access_token, refresh_token, user_id = row

    # Compose the reply email
    from email.mime.text import MIMEText
    import base64
    import email.utils

    message = MIMEText(reply_body)
    message['to'] = to_email
    message['subject'] = f"Re: {subject}"
    message['date'] = email.utils.formatdate()

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        send_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        payload = { "raw": raw }

        r = requests.post(send_url, headers=headers, json=payload)

        # 🔁 Retry if access token expired
        if r.status_code == 401:
            print("🔁 Access token expired. Refreshing...")

            if not refresh_token:
                session.clear()
                return jsonify({'logout': True}), 401

            new_token = refresh_access_token(user_id, refresh_token)
            if not new_token:
                session.clear()
                return jsonify({'logout': True}), 401

            headers["Authorization"] = f"Bearer {new_token}"
            r = requests.post(send_url, headers=headers, json=payload)

        if r.status_code == 200:
            return jsonify({"message": "Email sent successfully."})
        else:
            print("❌ Gmail send failed:", r.text)
            return jsonify({"error": "Failed to send email"}), 500

    except Exception as e:
        print("❌ Gmail send exception:", e)
        return jsonify({"error": "Server error"}), 500





@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return jsonify({'message': 'Logged out'}) # Redirect to homepage/login



if __name__ == '__main__':
    #create_tables()
    app.run(debug=True, host="0.0.0.0")
