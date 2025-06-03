import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(os.getenv("DATABASE_URL"))
cur = conn.cursor()
cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public';")
print("Tables:", cur.fetchall())
cur.close()
conn.close()
