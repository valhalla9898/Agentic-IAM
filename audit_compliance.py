"""Audit and compliance utilities

This module exposes convenience aliases and a small ComplianceFramework
enumeration used across the project.
"""
from enum import Enum
from agent_identity import AuditManager, ComplianceManager, AuditEventType


class ComplianceFramework(Enum):
	GDPR = 'gdpr'
	HIPAA = 'hipaa'
	SOX = 'sox'
	PCI_DSS = 'pci-dss'
	ISO_27001 = 'iso-27001'


__all__ = ['AuditManager', 'ComplianceManager', 'AuditEventType', 'ComplianceFramework']
