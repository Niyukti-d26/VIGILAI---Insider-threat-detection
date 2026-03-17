import uuid
import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="employee") # admin / employee
    department = Column(String)
    clearance_level = Column(Integer, default=1)
    risk_score = Column(Float, default=5.0)
    status = Column(String, default="normal") # normal / watch / blocked
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class File(Base):
    __tablename__ = "files"
    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False) # critical / research / general
    department = Column(String)
    size_label = Column(String)
    clearance_required = Column(Integer, default=1)
    risk_weight = Column(Integer, default=0)

class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"))
    file_id = Column(String, ForeignKey("files.id"))
    accessed_at = Column(DateTime, default=datetime.datetime.utcnow)
    denied = Column(Boolean, default=False)
    ip_address = Column(String)
    risk_delta = Column(Integer, default=0)
    session_id = Column(String)

    user = relationship("User")
    file = relationship("File")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True) # ALT-XXXX format
    user_id = Column(String, ForeignKey("users.id"))
    risk_score = Column(Float)
    type = Column(String) # info / suspicious / threat
    message = Column(String)
    dilithium_signature = Column(String)
    kyber_ciphertext_hash = Column(String)
    hash_algorithm = Column(String, default="SHA3-256")
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User")

class PQCSession(Base):
    __tablename__ = "pqc_sessions"
    id = Column(String, primary_key=True, default=generate_uuid)
    alert_id = Column(String, ForeignKey("alerts.id"))
    signature_verified = Column(Boolean, default=False)
    kyber_enc_hash = Column(String)
    dilithium_sig_hash = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    alert = relationship("Alert")
