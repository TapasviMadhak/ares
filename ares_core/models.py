"""
Database models for ARES
"""

from datetime import datetime
from typing import Optional, List
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, JSON,
    ForeignKey, Enum, Float, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()


class ScanStatus(PyEnum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(PyEnum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanMode(PyEnum):
    """Scan operation modes"""
    FULLY_AUTOMATED = "fully_automated"
    SEMI_AUTOMATED = "semi_automated"
    MANUAL = "manual"


class Scan(Base):
    """Scan session model"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), unique=True, nullable=False, index=True)
    target_url = Column(String(500), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    mode = Column(Enum(ScanMode), default=ScanMode.FULLY_AUTOMATED, nullable=False)
    
    # Configuration
    config = Column(JSON, nullable=True)  # Scan configuration
    scope = Column(JSON, nullable=True)  # In-scope URLs/domains
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Statistics
    pages_scanned = Column(Integer, default=0)
    requests_made = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    
    # Progress
    progress_percentage = Column(Float, default=0.0)
    current_phase = Column(String(100), nullable=True)
    
    # Results
    summary = Column(JSON, nullable=True)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan {self.scan_id} - {self.status.value}>"


class Vulnerability(Base):
    """Vulnerability finding model"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    
    # Identification
    vuln_id = Column(String(50), unique=True, nullable=False, index=True)
    vuln_type = Column(String(100), nullable=False, index=True)
    severity = Column(Enum(VulnerabilitySeverity), nullable=False, index=True)
    
    # Location
    url = Column(String(500), nullable=False)
    method = Column(String(10), nullable=True)  # GET, POST, etc.
    parameter = Column(String(200), nullable=True)
    
    # Details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    
    # Technical Details
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    
    # Metadata
    cvss_score = Column(Float, nullable=True)
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(100), nullable=True)
    
    # Confidence and Status
    confidence = Column(Float, default=0.5)  # 0.0 to 1.0
    is_false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    
    # Timestamps
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Additional data
    extra_metadata = Column(JSON, nullable=True)  # Renamed from 'metadata' to avoid SQLAlchemy reserved name conflict
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability {self.vuln_id} - {self.vuln_type} ({self.severity.value})>"


class ScanLog(Base):
    """Scan activity log"""
    __tablename__ = "scan_logs"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    level = Column(String(20), nullable=False)  # INFO, WARNING, ERROR
    category = Column(String(50), nullable=True)  # e.g., 'crawler', 'scanner', 'ai'
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="logs")
    
    def __repr__(self):
        return f"<ScanLog {self.level} - {self.message[:50]}>"


class TrainingData(Base):
    """Training data for model fine-tuning"""
    __tablename__ = "training_data"
    
    id = Column(Integer, primary_key=True)
    
    # Data source
    source = Column(String(100), nullable=False)  # e.g., 'bug_bounty', 'cve', 'manual'
    source_url = Column(String(500), nullable=True)
    
    # Content
    vulnerability_type = Column(String(100), nullable=False, index=True)
    context = Column(Text, nullable=False)  # The vulnerable code/request
    payload = Column(Text, nullable=True)  # Exploit payload
    description = Column(Text, nullable=False)
    
    # Metadata
    severity = Column(Enum(VulnerabilitySeverity), nullable=True)
    tags = Column(JSON, nullable=True)
    
    # Quality
    quality_score = Column(Float, default=0.5)  # 0.0 to 1.0
    is_validated = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f"<TrainingData {self.vulnerability_type} from {self.source}>"


class AIDecision(Base):
    """AI decision log for reinforcement learning"""
    __tablename__ = "ai_decisions"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    
    # State
    state = Column(JSON, nullable=False)  # Application state when decision was made
    
    # Action
    action = Column(String(100), nullable=False)
    action_parameters = Column(JSON, nullable=True)
    
    # Outcome
    reward = Column(Float, nullable=True)  # Reinforcement learning reward
    outcome = Column(JSON, nullable=True)  # Result of the action
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    
    def __repr__(self):
        return f"<AIDecision {self.action} -> reward: {self.reward}>"


class KnowledgeBase(Base):
    """RAG knowledge base for security information"""
    __tablename__ = "knowledge_base"
    
    id = Column(Integer, primary_key=True)
    
    # Content
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=False)
    content_type = Column(String(50), nullable=False)  # 'cve', 'technique', 'tool', etc.
    
    # Embedding for RAG
    embedding = Column(JSON, nullable=True)  # Store as JSON array
    
    # Metadata
    source = Column(String(200), nullable=True)
    tags = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Indexes for efficient search
    __table_args__ = (
        Index('idx_knowledge_content_type', 'content_type'),
    )
    
    def __repr__(self):
        return f"<KnowledgeBase {self.content_type} - {self.title}>"


class UserInteraction(Base):
    """Track user interventions in semi-automated mode"""
    __tablename__ = "user_interactions"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    
    # Interaction details
    interaction_type = Column(String(50), nullable=False)  # 'pause', 'resume', 'approve', 'reject', 'modify'
    ai_suggestion = Column(JSON, nullable=True)  # What AI suggested
    user_decision = Column(JSON, nullable=False)  # What user decided
    
    # Timestamp
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    def __repr__(self):
        return f"<UserInteraction {self.interaction_type}>"
