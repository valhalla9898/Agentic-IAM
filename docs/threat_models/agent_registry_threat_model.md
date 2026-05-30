# Threat Model — Agent Registry

## Overview
Threat model for the Agent Registry service which stores agent identities and metadata.

## Assets
- Agent identities and key material
- Registration endpoints
- Registry database

## Threats
- Unauthorized registration (fake agents)
- Data tampering or unauthorized modification
- Leakage of private keys

## Mitigations
- Enforce strong identity proofs during registration
- Sign and verify agent records
- Role-based access control for registry APIs
- Regular key rotation and limited key exposure
