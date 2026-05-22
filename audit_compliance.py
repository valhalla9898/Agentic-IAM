"""Audit and compliance utilities

This module exposes convenience aliases and a small ComplianceFramework
enumeration used across the project.
"""
from enum import Enum
from agent_identity import AuditManager, ComplianceManager, AuditEventType


class EventSeverity(Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


class AuditEvent:
    def __init__(
        self,
        event_id,
        event_type,
        timestamp,
        severity,
        component,
        outcome,
        agent_id=None,
        source_ip=None,
        user_agent=None,
        details=None,
        **kwargs,
    ):
        self.event_id = event_id
        self.event_type = event_type
        self.timestamp = timestamp
        self.severity = severity
        self.component = component
        self.outcome = outcome
        self.agent_id = agent_id
        self.source_ip = source_ip
        self.user_agent = user_agent
        self.details = details or {}
        for key, value in kwargs.items():
            setattr(self, key, value)


class ComplianceFramework(Enum):
    GDPR = 'gdpr'
    HIPAA = 'hipaa'
    SOX = 'sox'
    PCI_DSS = 'pci-dss'
    PCI_DSS_V4 = 'pci-dss-v4'
    NIST_CSF = 'nist-csf'
    ISO_27001 = 'iso-27001'


__all__ = [
    'AuditManager',
    'ComplianceManager',
    'AuditEventType',
    'ComplianceFramework',
    'AuditEvent',
    'EventSeverity',
]
