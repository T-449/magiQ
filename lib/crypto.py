"""
Post-quantum primitives and application-level certificates.

XMSS goes through libxmss_helper via ctypes, ML-DSA-65 through liboqs-python.
"""

import ctypes
import json
import os
import time
import uuid

import oqs

from lib.common import load_config, debug, b64e, b64d

_CFG = load_config()

XMSS_ALGO = _CFG["algorithms"]["xmss"]
MLDSA_ALGO = _CFG["algorithms"]["mldsa"]


class XMSSWrapper:
    """Handle-based XMSS keygen, sign and verify."""

    def __init__(self, lib_path=None):
        if lib_path is None:
            lib_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "libxmss_helper.so")
        if not os.path.exists(lib_path):
            raise FileNotFoundError(
                f"{lib_path} not found. Run ./setup.sh to compile it.")
        self._lib = ctypes.CDLL(lib_path)
        self._declare_signatures()
        self._lib.xmss_init()
        debug("XMSS", f"loaded {lib_path}")

    def _declare_signatures(self):
        lib = self._lib
        u8p = ctypes.POINTER(ctypes.c_uint8)
        sizep = ctypes.POINTER(ctypes.c_size_t)

        lib.xmss_init.restype = ctypes.c_int
        lib.xmss_pk_length.argtypes = [ctypes.c_char_p]
        lib.xmss_pk_length.restype = ctypes.c_size_t
        lib.xmss_sig_length.argtypes = [ctypes.c_char_p]
        lib.xmss_sig_length.restype = ctypes.c_size_t
        lib.xmss_keygen.argtypes = [ctypes.c_char_p]
        lib.xmss_keygen.restype = ctypes.c_int
        lib.xmss_get_pk.argtypes = [ctypes.c_int, u8p, sizep]
        lib.xmss_get_pk.restype = ctypes.c_int
        lib.xmss_sign.argtypes = [ctypes.c_int, u8p, ctypes.c_size_t,
                                  u8p, sizep]
        lib.xmss_sign.restype = ctypes.c_int
        lib.xmss_verify.argtypes = [ctypes.c_char_p, u8p, ctypes.c_size_t,
                                    u8p, ctypes.c_size_t, u8p, ctypes.c_size_t]
        lib.xmss_verify.restype = ctypes.c_int
        lib.xmss_free_handle.argtypes = [ctypes.c_int]
        lib.xmss_free_handle.restype = None
        lib.xmss_cleanup.restype = None

    def pk_length(self, algo=None):
        return self._lib.xmss_pk_length((algo or XMSS_ALGO).encode())

    def sig_length(self, algo=None):
        return self._lib.xmss_sig_length((algo or XMSS_ALGO).encode())

    def keygen(self, algo=None):
        algo = algo or XMSS_ALGO
        t0 = time.time()
        handle = self._lib.xmss_keygen(algo.encode())
        if handle < 0:
            raise RuntimeError(f"XMSS keygen failed for {algo}")
        debug("XMSS", f"keygen {time.time() - t0:.1f}s handle={handle}")

        pk_len = self.pk_length(algo)
        buf = (ctypes.c_uint8 * pk_len)()
        out = ctypes.c_size_t(0)
        if self._lib.xmss_get_pk(handle, buf, ctypes.byref(out)) != 0:
            raise RuntimeError("xmss_get_pk failed")
        return handle, bytes(buf[:out.value])

    def sign(self, handle, message: bytes, algo=None):
        algo = algo or XMSS_ALGO
        sig_buf = (ctypes.c_uint8 * self.sig_length(algo))()
        sig_len = ctypes.c_size_t(0)
        # from_buffer_copy does one bulk memcpy. Splatting the message would
        # push every byte as a separate Python argument, which is roughly
        # 2000x slower on a 48 KB m_0 and would dominate the measured cost.
        msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        if self._lib.xmss_sign(handle, msg_buf, len(message),
                               sig_buf, ctypes.byref(sig_len)) != 0:
            raise RuntimeError("XMSS sign failed")
        return bytes(sig_buf[:sig_len.value])

    def verify(self, message: bytes, signature: bytes, pk: bytes, algo=None):
        algo = algo or XMSS_ALGO
        msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
        sig_buf = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
        pk_buf = (ctypes.c_uint8 * len(pk)).from_buffer_copy(pk)
        rc = self._lib.xmss_verify(algo.encode(), msg_buf, len(message),
                                   sig_buf, len(signature), pk_buf, len(pk))
        return rc == 0

    def free(self, handle):
        self._lib.xmss_free_handle(handle)

    def cleanup(self):
        self._lib.xmss_cleanup()


class MLDSAWrapper:
    """ML-DSA-65 keygen, sign and verify via liboqs-python."""

    def __init__(self, algo=None):
        self.algo = algo or MLDSA_ALGO

    def keygen(self):
        sig = oqs.Signature(self.algo)
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return bytes(pk), bytes(sk)

    def sign(self, message: bytes, sk: bytes):
        sig = oqs.Signature(self.algo, secret_key=sk)
        return bytes(sig.sign(message))

    def verify(self, message: bytes, signature: bytes, pk: bytes):
        verifier = oqs.Signature(self.algo)
        try:
            verifier.verify(message, signature, pk)
            return True
        except Exception as e:
            debug("MLDSA", f"verify failed: {e}")
            return False


def build_cert_body(subject, public_key, key_algorithm, issuer,
                    validity_days=365):
    now = time.time()
    return {
        "version": 1,
        "serial": uuid.uuid4().hex,
        "subject": subject,
        "public_key_b64": b64e(public_key),
        "key_algorithm": key_algorithm,
        "issuer": issuer,
        "issued_at": now,
        "expires_at": now + validity_days * 86400,
    }


def cert_body_bytes(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def issue_certificate(body, ca_sk, mldsa):
    cert = dict(body)
    cert["signature_algorithm"] = mldsa.algo
    cert["signature_b64"] = b64e(mldsa.sign(cert_body_bytes(body), ca_sk))
    return cert


def verify_certificate(cert, ca_pk, mldsa):
    signature = cert.get("signature_b64", "")
    if not signature:
        return False
    body = {k: v for k, v in cert.items()
            if k not in ("signature_algorithm", "signature_b64")}
    return mldsa.verify(cert_body_bytes(body), b64d(signature), ca_pk)


def pk_from_cert(cert):
    return b64d(cert["public_key_b64"])
