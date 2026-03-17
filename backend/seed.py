import datetime
from passlib.context import CryptContext
from database import SessionLocal, engine, Base
from models import User, File, AccessLog

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str):
    # Depending on the passlib version mapped to bcrypt, it may require bytes or string.
    # Newest bcrypt requires bytes to bypass the TypeError, but passlib usually handles it.
    # To be safe across versions, we try standard hash, if it fails due to TypeError, we pass bytes.
    try:
        return pwd_context.hash(password)
    except TypeError:
        return pwd_context.hash(password.encode("utf-8"))

def seed_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    if db.query(User).count() > 0:
        db.close()
        return

    # Create Users
    users = [
        User(name="Alex Morgan", email="admin@vigilai.io", password_hash=get_password_hash("admin123"), role="admin", department="Security Operations", clearance_level=3),
        User(name="Sarah Chen", email="sarah@vigilai.io", password_hash=get_password_hash("sarah123"), role="employee", department="Engineering", clearance_level=1),
        User(name="Maya Torres", email="maya@vigilai.io", password_hash=get_password_hash("maya123"), role="employee", department="Finance", clearance_level=2),
        User(name="Raj Patel", email="raj@vigilai.io", password_hash=get_password_hash("raj123"), role="employee", department="R&D", clearance_level=2),
    ]
    db.add_all(users)
    db.commit()

    # Create Files
    files = [
        # Critical
        File(name="Project Helios Research Data.zip", type="critical", department="R&D", size_label="847 MB", clearance_required=3, risk_weight=28),
        File(name="Q4 Financial Report.xlsx", type="critical", department="Finance", size_label="2.4 MB", clearance_required=3, risk_weight=24),
        File(name="Merger Negotiation Docs.pdf", type="critical", department="Legal", size_label="14.2 MB", clearance_required=3, risk_weight=30),
        File(name="Executive Compensation 2025.xlsx", type="critical", department="HR/Finance", size_label="890 KB", clearance_required=3, risk_weight=22),
        # Research
        File(name="API Architecture v3.pdf", type="research", department="Engineering", size_label="5.1 MB", clearance_required=2, risk_weight=5),
        File(name="ML Model Weights v2.bin", type="research", department="AI Lab", size_label="1.2 GB", clearance_required=2, risk_weight=6),
        File(name="System Design Diagrams Q3.pptx", type="research", department="Engineering", size_label="18 MB", clearance_required=2, risk_weight=4),
        File(name="Competitor Analysis 2025.pdf", type="research", department="Strategy", size_label="6.8 MB", clearance_required=2, risk_weight=7),
        # General
        File(name="Employee Handbook 2025.pdf", type="general", department="HR", size_label="1.8 MB", clearance_required=1, risk_weight=0),
        File(name="IT Security Policy v4.pdf", type="general", department="IT", size_label="340 KB", clearance_required=1, risk_weight=0),
        File(name="Office 365 Setup Guide.docx", type="general", department="IT", size_label="2.1 MB", clearance_required=1, risk_weight=1),
        File(name="Q3 All-Hands Slides.pptx", type="general", department="Comms", size_label="8.4 MB", clearance_required=1, risk_weight=0),
    ]
    db.add_all(files)
    db.commit()

    # Create Baseline Access Logs
    # 6 historical normal access logs per employee
    # No baseline access logs — everyone starts at 0% risk
    db.commit()
    db.close()
    print("Database seeded with users, files, and baseline access logs.")

if __name__ == "__main__":
    seed_db()
