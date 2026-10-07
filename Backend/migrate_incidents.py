import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "cybertwin.db"


def main():

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            finding_id INTEGER NOT NULL,

            asset_id INTEGER NOT NULL,

            title TEXT NOT NULL,

            severity TEXT NOT NULL,

            status TEXT NOT NULL DEFAULT 'open',

            description TEXT,

            vulnerability_type TEXT,

            affected_component TEXT,

            host TEXT,

            port TEXT,

            endpoint TEXT,

            database_name TEXT,

            file_path TEXT,

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()

    print("Incident table migration completed successfully.")

    cursor.execute("PRAGMA table_info(incidents)")

    columns = cursor.fetchall()

    print("\nIncident table columns:")

    for column in columns:
        print(f"- {column[1]}")

    connection.close()


if __name__ == "__main__":
    main()