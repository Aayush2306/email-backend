from db import get_conn, put_conn

def create_tables():
    conn = get_conn()
    cur = conn.cursor()

    # ⚠️ DROP tables first (order matters due to foreign key)
    cur.execute("DROP TABLE IF EXISTS emails;")
    cur.execute("DROP TABLE IF EXISTS usersvibe;")

    # ✅ Recreate users table
    cur.execute("""
        CREATE TABLE usersvibe (
            id SERIAL PRIMARY KEY,
            google_id TEXT UNIQUE,
            name TEXT,
            email TEXT UNIQUE,
            picture TEXT,
            tone TEXT,
            preferences TEXT,
            access_token TEXT,
            refresh_token TEXT,
            setup_complete BOOLEAN DEFAULT FALSE,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # ✅ Recreate emails table
    cur.execute("""
        CREATE TABLE emails (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES usersvibe(id),
            gmail_id TEXT,
            sender TEXT,
            subject TEXT,
            body TEXT,
            is_important BOOLEAN DEFAULT FALSE,
            ai_reply TEXT,
            reply_status TEXT DEFAULT 'pending',
            received_at TIMESTAMP
        );
    """)

    conn.commit()
    cur.close()
    put_conn(conn)
