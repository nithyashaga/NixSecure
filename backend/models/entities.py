from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from database.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    device_name = Column(String(120), nullable=False, unique=True)
    device_type = Column(String(50), nullable=False)
    operating_system = Column(String(100), nullable=False)
    department = Column(String(100), nullable=False)
    status = Column(String(30), default="Active")
    failed_login_attempts = Column(Integer, default=0)
    open_ports = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_vulnerabilities = Column(Integer, default=0)
    patch_age_days = Column(Integer, default=0)
    network_anomaly_score = Column(Float, default=0)
    malware_alerts = Column(Integer, default=0)
    privilege_escalation_attempts = Column(Integer, default=0)
    previous_security_incidents = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    predictions = relationship("Prediction", back_populates="device", cascade="all, delete-orphan")

class Prediction(Base):
    __tablename__ = "predictions"
    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    prediction_time = Column(DateTime, default=datetime.utcnow)
    contributing_factors = Column(Text, default="[]")
    device = relationship("Device", back_populates="predictions")
