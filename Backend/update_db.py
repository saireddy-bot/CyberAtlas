import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cybertwin.db"

connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()

columns = [
    ("host", "TEXT"),
    ("port", "TEXT"),
    ("endpoint", "TEXT"),
    ("database_name", "TEXT"),
    ("file_path", "TEXT"),
]

for column_name, column_type in columns:
    try:
        cursor.execute(
            f"ALTER TABLE security_findings ADD COLUMN {column_name} {column_type}"
        )
        print(f"Added column: {column_name}")
    except sqlite3.OperationalError as error:
        if "duplicate column name" in str(error).lower():
            print(f"Already exists: {column_name}")
        else:
            raise

connection.commit()
connection.close()

print("Database update completed successfully.")