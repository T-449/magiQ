"""
ca.py - Certificate Authority

Issues certificates and distributes provider info to users.
"""

from lib.common import (
    load_config, sha256_hex,
    keys_dir, certs_dir, save_bytes, save_json, safe_name,
)
from lib.crypto import (
    MLDSAWrapper, build_cert_body, issue_certificate,
    verify_certificate, pk_from_cert,
)

_CFG = load_config()


class CertificateAuthority:

    def __init__(self):
        self.name = _CFG["ca"]["name"]
        self.mldsa = MLDSAWrapper()
        self.pk = None
        self._sk = None
        self._provider_info = None  # set when provider registers
        print(f"[CA] '{self.name}' created")

    def init_keys(self):
        print(f"[CA] Generating ML-DSA-65 key pair ...")
        self.pk, self._sk = self.mldsa.keygen()
        kd = keys_dir("ca")
        save_bytes(self.pk, f"{kd}/mldsa_pk.bin")
        save_bytes(self._sk, f"{kd}/mldsa_sk.bin")
        print(f"[CA] pk={len(self.pk)}B  fp={sha256_hex(self.pk)[:16]}...")

    def issue_cert(self, subject, pk, key_algo):
        body = build_cert_body(subject, pk, key_algo, self.name)
        cert = issue_certificate(body, self._sk, self.mldsa)
        save_json(cert, f"{certs_dir('ca')}/{safe_name(subject)}.json")
        print(f"[CA] Cert -> '{subject}'  serial={cert['serial'][:8]}...")
        return cert

    def verify_cert(self, cert):
        return verify_certificate(cert, self.pk, self.mldsa)

    def get_public_key(self):
        return self.pk

    #  Provider registration with CA 

    def register_provider(self, tls_cert, id_cert):
        """Store provider certs so users can retrieve them."""
        self._provider_info = {
            "tls_cert": tls_cert,
            "id_cert": id_cert,
        }
        print(f"[CA] Provider certs registered for distribution")

    def get_provider_info(self):
        """Users call this to obtain the provider's verified certs.

        Returns dict with tls_cert, id_cert and the extracted public keys:
          tls_pk  (ML-DSA-65, for app-level TLS cert)
          id_pk   (XMSS, for signing agent confirmations)
        """
        if self._provider_info is None:
            raise RuntimeError("No provider registered with CA")
        info = dict(self._provider_info)
        info["tls_pk"] = pk_from_cert(info["tls_cert"])
        info["id_pk"] = pk_from_cert(info["id_cert"])
        return info