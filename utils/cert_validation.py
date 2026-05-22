from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import datetime
import logging

logger = logging.getLogger("utils.cert_validation")


def validate_pem_certificate(pem_data: str, require_cn: bool = True) -> bool:
    """Validate a PEM-encoded certificate string.

    Checks: parseable PEM, validity period (not before / not after).
    This is intentionally lightweight — production deployments should
    perform OCSP/CRL checks and truststore validation.
    """
    try:
        if not pem_data or not pem_data.strip():
            logger.debug("Empty PEM data")
            return False

        # Some proxies send a combined header with attributes; try to extract PEM if present
        if "-----BEGIN CERTIFICATE-----" not in pem_data:
            # Attempt to locate base64 block
            start = pem_data.find("MI")
            if start != -1:
                pem_candidate = pem_data[start:]
                # Wrap as PEM
                pem_data = "-----BEGIN CERTIFICATE-----\n" + pem_candidate + "\n-----END CERTIFICATE-----"

        cert = x509.load_pem_x509_certificate(pem_data.encode('utf-8'), default_backend())

        now = datetime.datetime.utcnow()
        if cert.not_valid_before > now or cert.not_valid_after < now:
            logger.warning("Certificate not within validity period")
            return False

        if require_cn:
            try:
                subject = cert.subject
                cn = None
                for attr in subject:
                    if attr.oid == NameOID.COMMON_NAME:
                        cn = attr.value
                        break
                if not cn:
                    logger.warning("Certificate missing CN")
                    return False
            except Exception:
                logger.exception("Failed to parse certificate subject")
                return False

        # TODO: Add OCSP/CRL and truststore checks in production
        return True

    except Exception:
        logger.exception("Failed to validate PEM certificate")
        return False
