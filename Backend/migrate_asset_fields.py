import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cybertwin.db"

connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()

columns = [
    ("data_sensitivity", "INTEGER NOT NULL DEFAULT 5"),
    ("operational_dependency", "INTEGER NOT NULL DEFAULT 5"),
    ("customer_impact", "INTEGER NOT NULL DEFAULT 5"),
    ("financial_impact", "INTEGER NOT NULL DEFAULT 5"),
]

existing_columns = {
    row[1]
    for row in cursor.execute("PRAGMA table_info(assets)")
}

for column_name, column_definition in columns:
    if column_name not in existing_columns:
        cursor.execute(
            f"ALTER TABLE assets ADD COLUMN "
            f"{column_name} {column_definition}"
        )
        print(f"Added column: {column_name}")
    else:
        print(f"Already exists: {column_name}")

connection.commit()
connection.close()

print("Asset table migration completed successfully.")