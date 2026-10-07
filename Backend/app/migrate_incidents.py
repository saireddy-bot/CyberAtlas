from sqlalchemy import inspect, text

from app.database import engine


def migrate():
    inspector = inspect(engine)

    tables = inspector.get_table_names()

    if "security_incidents" in tables:
        print("Already exists: security_incidents")
        print("Security incident migration completed successfully.")
        return

    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE security_incidents (
                id INTEGER PRIMARY KEY,
                finding_id INTEGER NOT NULL,
                asset_id INTEGER NOT NULL,
                title VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                status VARCHAR NOT NULL DEFAULT 'open',
                description TEXT,
                vulnerability_type VARCHAR,
                affected_component VARCHAR,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """))

    print("Created: security_incidents")
    print("Security incident migration completed successfully.")


if __name__ == "__main__":
    migrate()