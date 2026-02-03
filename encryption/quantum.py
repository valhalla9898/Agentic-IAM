# Quantum-Resistant Encryption Algorithms

This module implements post-quantum cryptographic algorithms for secure communications.

## Algorithms Supported
- CRYSTALS-Kyber (Key Encapsulation)
- CRYSTALS-Dilithium (Digital Signatures)
- Falcon (Alternative signature scheme)

## Features
- Hybrid encryption (classical + quantum-resistant)
- Key management for quantum threats
- Integration with existing TLS

## Usage
```python
from encryption.quantum import QuantumEncryptor

encryptor = QuantumEncryptor()
encrypted = encryptor.encrypt(data, public_key)
```