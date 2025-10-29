"""
Database models for WebSecScanner
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, ForeignKey, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    """User model"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    organizations = relationship("Organization", secondary="user_organizations", back_populates="users")


class Organization(Base):
    """Organization/Company model"""
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    users = relationship("User", secondary="user_organizations", back_populates="organizations")
    scans = relationship("Scan", back_populates="organization")


class UserOrganization(Base):
    """User-Organization association table"""
    __tablename__ = "user_organizations"
    
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), primary_key=True)
    role = Column(String(50), default="member")  # admin, member, viewer
    joined_at = Column(DateTime, default=datetime.utcnow)


class Scan(Base):
    """Security scan model"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, index=True, nullable=False)
    target_url = Column(String(500), nullable=False)
    scan_status = Column(String(50), default="pending")  # pending, running, completed, failed
    scan_types = Column(JSON)
    parameters_tested = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="INFO")
    severity_distribution = Column(JSON)
    scan_duration = Column(Float)
    scan_date = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    # Foreign keys
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    # Relationships
    user = relationship("User", back_populates="scans")
    organization = relationship("Organization", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    """Vulnerability finding model"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    vuln_type = Column(String(100), nullable=False)
    subtype = Column(String(100))
    severity = Column(String(20), nullable=False)
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))
    
    location = Column(String(500))
    parameter = Column(String(255))
    payload = Column(Text)
    evidence = Column(Text)
    
    description = Column(Text)
    remediation = Column(Text)
    confidence = Column(String(20))
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    scan = relationship("Scan", back_populates="vulnerabilities")
