"""Simple secret rotation helper.

Usage:
    python scripts/secret_rotate.py SECRET_NAME [--length 32] [--write-local]

This will generate a secure random value and attempt to store it in Azure Key Vault
if `AZURE_KEYVAULT_URL` is configured. Otherwise it writes to `data/secrets/{NAME}`.
"""
import os
import argparse
import secrets
from pathlib import Path

from secrets.key_vault import SecretManager


def generate_secret(length: int = 32) -> str:
    return secrets.token_urlsafe(length)[:length]


def write_local(name: str, value: str):
    p = Path(__file__).parent.parent / 'data' / 'secrets'
    p.mkdir(parents=True, exist_ok=True)
    fp = p / name
    fp.write_text(value, encoding='utf-8')
    print(f'Wrote secret to {fp}')


def rotate(name: str, length: int = 32, write_local_fallback: bool = True):
    sm = SecretManager()
    new = generate_secret(length)
    # Try Azure Key Vault
    if sm.azure_vault_url:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient

            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=sm.azure_vault_url, credential=credential)
            client.set_secret(name, new)
            print(f'Set secret {name} in Azure Key Vault')
            return new
        except Exception as e:
            print(f'Azure Key Vault set failed: {e} — falling back')

    if write_local_fallback:
        write_local(name, new)
    return new


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('name')
    parser.add_argument('--length', type=int, default=32)
    parser.add_argument('--no-local', dest='local', action='store_false')
    args = parser.parse_args()

    new = rotate(args.name, length=args.length, write_local_fallback=args.local)
    print('New secret:', new)


if __name__ == '__main__':
    main()
