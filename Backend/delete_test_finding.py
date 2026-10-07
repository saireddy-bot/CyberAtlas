from app.database import SessionLocal
from app.models import SecurityFinding

db = SessionLocal()

finding = db.query(SecurityFinding).filter(
    SecurityFinding.id == 4
).first()

if finding:
    db.delete(finding)
    db.commit()
    print("Finding ID 4 deleted successfully.")
else:
    print("Finding ID 4 not found.")

db.close()