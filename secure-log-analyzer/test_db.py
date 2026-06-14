import psycopg2

DATABASE_URL = "postgresql://neondb_owner:npg_p0GmET1UHzvL@ep-purple-lab-ahy9d97a-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require"

try:
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT version();")
    print("SUCCESS:", cur.fetchone())
    conn.close()

except Exception as e:
    print("ERROR:", e)