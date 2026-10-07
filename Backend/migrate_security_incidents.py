from app.database import engine
from app.models import SecurityIncident

print("Creating security_incidents table...")

SecurityIncident.__table__.create(
    bind=engine,
    checkfirst=True
)

print("Security incidents table created successfully.")