import sqlite3

conn = sqlite3.connect("cybertwin.db")
cursor = conn.cursor()

cursor.execute("""
UPDATE assets
SET risk_level = 'Low'
WHERE risk_level IS NULL OR risk_level = ''
""")

conn.commit()

print("Existing assets updated:", cursor.rowcount)

conn.close()