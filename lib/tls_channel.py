"""
PQ-mTLS transport.

Generates ML-DSA-65 X.509 certificates with the openssl CLI, which needs either
oqs-provider or OpenSSL 3.5 or newer, and provides a small framed-JSON
request/response server and client on top of TLS 1.3.

The application-level crypto in lib/crypto.py is independent of this transport.
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import threading
from collections import defaultdict

from lib.common import load_config, debug

_CFG = load_config()

# Message framing: 4-byte length prefix followed by a JSON payload.
_HDR = struct.Struct("!I")


def _run_openssl(args, check=True):
    cmd = ["openssl"] + args
    debug("TLS", f"exec: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if check and r.returncode != 0:
        raise RuntimeError(f"openssl failed: {r.stderr.strip()}")
    return r.returncode, r.stdout, r.stderr


def detect_pq_tls():
    """Return the openssl provider flags needed for ML-DSA-65, or None.

    An empty list means ML-DSA-65 works with no extra flags.
    """
    try:
        rc, _, _ = _run_openssl(
            ["genpkey", "-algorithm", "mldsa65", "-out", "/dev/null"],
            check=False)
        if rc == 0:
            return []
    except Exception:
        pass
    try:
        rc, _, _ = _run_openssl(
            ["genpkey", "-provider", "oqsprovider", "-provider", "default",
             "-algorithm", "mldsa65", "-out", "/dev/null"],
            check=False)
        if rc == 0:
            return ["-provider", "oqsprovider", "-provider", "default"]
    except Exception:
        pass
    return None


def generate_tls_certs(cert_dir):
    """Generate an ML-DSA-65 CA plus server and client certs for PQ mTLS."""
    os.makedirs(cert_dir, exist_ok=True)
    paths = {
        "ca_key": os.path.join(cert_dir, "ca_key.pem"),
        "ca_cert": os.path.join(cert_dir, "ca_cert.pem"),
        "server_key": os.path.join(cert_dir, "server_key.pem"),
        "server_cert": os.path.join(cert_dir, "server_cert.pem"),
        "server_csr": os.path.join(cert_dir, "server.csr"),
        "client_key": os.path.join(cert_dir, "client_key.pem"),
        "client_cert": os.path.join(cert_dir, "client_cert.pem"),
        "client_csr": os.path.join(cert_dir, "client.csr"),
    }

    prov = detect_pq_tls()
    if prov is None:
        raise RuntimeError(
            "ML-DSA-65 is not available in openssl. PQ TLS is mandatory.\n"
            "Run ./setup.sh to build oqs-provider, or install OpenSSL >= 3.5.")
    print("[TLS] Using ML-DSA-65 for TLS X.509 certificates")

    _run_openssl(prov + ["genpkey", "-algorithm", "mldsa65",
                         "-out", paths["ca_key"]])
    _run_openssl(prov + [
        "req", "-new", "-x509",
        "-key", paths["ca_key"],
        "-out", paths["ca_cert"],
        "-days", "365",
        "-subj", f"/CN={_CFG['ca']['name']}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign"])

    _run_openssl(prov + ["genpkey", "-algorithm", "mldsa65",
                         "-out", paths["server_key"]])
    _run_openssl(prov + [
        "req", "-new",
        "-key", paths["server_key"],
        "-out", paths["server_csr"],
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"])
    _run_openssl(prov + [
        "x509", "-req",
        "-in", paths["server_csr"],
        "-CA", paths["ca_cert"],
        "-CAkey", paths["ca_key"],
        "-CAcreateserial",
        "-out", paths["server_cert"],
        "-days", "365",
        "-copy_extensions", "copyall"])

    _run_openssl(prov + ["genpkey", "-algorithm", "mldsa65",
                         "-out", paths["client_key"]])
    _run_openssl(prov + [
        "req", "-new",
        "-key", paths["client_key"],
        "-out", paths["client_csr"],
        "-subj", "/CN=pq-client"])
    _run_openssl(prov + [
        "x509", "-req",
        "-in", paths["client_csr"],
        "-CA", paths["ca_cert"],
        "-CAkey", paths["ca_key"],
        "-CAcreateserial",
        "-out", paths["client_cert"],
        "-days", "365"])

    for tmp in (paths["server_csr"], paths["client_csr"],
                os.path.join(cert_dir, "ca_cert.srl")):
        if os.path.exists(tmp):
            os.remove(tmp)

    print(f"[TLS] PQ certificates generated in {cert_dir}/")
    return paths


_KEX_GROUPS = f"{_CFG['algorithms']['kex']}:X25519:secp384r1"


def _apply_pq_kex_groups(ctx):
    """Prefer the configured PQ-hybrid key exchange group.

    Python only recently grew an API for the TLS 1.3 group list, and
    set_ecdh_curve() rejects hybrid names outright. Where neither works the
    OpenSSL default preference applies, and OpenSSL 3.5 and later, which
    setup.sh already requires, puts X25519MLKEM768 first.
    """
    set_groups = getattr(ctx, "set_groups", None)
    if set_groups is not None:
        set_groups(_KEX_GROUPS)
        debug("TLS", f"KEX groups pinned to {_KEX_GROUPS}")
        return
    try:
        ctx.set_ecdh_curve(_CFG["algorithms"]["kex"])
        debug("TLS", f"KEX curve pinned to {_CFG['algorithms']['kex']}")
    except (ValueError, AttributeError):
        debug("TLS", f"no API to pin {_KEX_GROUPS}, "
                     "using the OpenSSL default group preference")


def make_server_context(cert_paths, require_client_cert=True):
    """Build a TLS 1.3 server context configured for PQ mTLS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=cert_paths["server_cert"],
                        keyfile=cert_paths["server_key"])
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=cert_paths["ca_cert"])
    _apply_pq_kex_groups(ctx)
    return ctx


def make_client_context(cert_paths):
    """Build a TLS 1.3 client context that presents a PQ client cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=cert_paths["ca_cert"])
    ctx.load_cert_chain(certfile=cert_paths["client_cert"],
                        keyfile=cert_paths["client_key"])
    _apply_pq_kex_groups(ctx)
    return ctx


def make_listening_socket(host, port, backlog=5, accept_timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(accept_timeout)
    s.bind((host, port))
    s.listen(backlog)
    return s


def open_tls_client(ctx, host, port, timeout=30, server_hostname="localhost"):
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect((host, port))
    return ctx.wrap_socket(raw, server_hostname=server_hostname)


class TLSServer:
    """Serves one request per connection, one connection at a time."""

    def __init__(self, cert_paths, handler_fn):
        """handler_fn takes a request dict and returns a response dict."""
        self.cert_paths = cert_paths
        self.handler_fn = handler_fn
        self._ctx = make_server_context(cert_paths)
        self._sock = None
        self._thread = None
        self._running = False

    def start(self, host=None, port=None):
        host = host or _CFG["provider"]["host"]
        port = port or _CFG["provider"]["port"]
        self._sock = make_listening_socket(host, port)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        debug("TLS", f"server listening on {host}:{port}")

    def _serve(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with self._ctx.wrap_socket(conn, server_side=True) as tls:
                    req = recv_msg(tls)
                    if req is not None:
                        send_msg(tls, self.handler_fn(req))
            except Exception as e:
                debug("TLS", f"error from {addr}: {e}")

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=3)


class TLSClient:
    """Sends one request dict per connection and records payload sizes."""

    def __init__(self, cert_paths):
        self.cert_paths = cert_paths
        self._ctx = make_client_context(cert_paths)
        self._bw_by_action = defaultdict(
            lambda: {"sent": 0, "recv": 0, "msg_sent": 0, "msg_recv": 0})
        self._last_request_bw = None

    def _record_bandwidth(self, action, sent_bytes, recv_bytes, recv_ok):
        stats = self._bw_by_action[action]
        stats["sent"] += sent_bytes
        stats["msg_sent"] += 1
        stats["recv"] += recv_bytes
        if recv_ok:
            stats["msg_recv"] += 1
        self._last_request_bw = {
            "action": action,
            "sent": sent_bytes,
            "recv": recv_bytes,
            "msg_sent": 1,
            "msg_recv": 1 if recv_ok else 0,
        }

    def pop_last_request_bandwidth(self):
        bw = self._last_request_bw
        self._last_request_bw = None
        return bw

    def bandwidth_by_action(self):
        return {k: dict(v) for k, v in self._bw_by_action.items()}

    def request(self, data, host=None, port=None):
        host = host or _CFG["provider"]["host"]
        port = port or _CFG["provider"]["port"]
        tls = open_tls_client(self._ctx, host, port, timeout=120)

        action = data.get("action", "unknown") if isinstance(data, dict) else "unknown"
        sent_bytes = framed_json_size(data)
        recv_bytes = 0
        recv_ok = False
        try:
            send_msg(tls, data)
            resp = recv_msg(tls)
            if resp is not None:
                recv_bytes = framed_json_size(resp)
                recv_ok = True
            return resp
        finally:
            self._record_bandwidth(action, sent_bytes, recv_bytes, recv_ok)
            tls.close()


def _json_default(o):
    if isinstance(o, bytes):
        return o.hex()
    raise TypeError(f"Not JSON serializable: {type(o)}")


def send_msg(conn, obj):
    """Send a dict as a length-prefixed JSON message."""
    payload = json.dumps(obj, default=_json_default).encode()
    conn.sendall(_HDR.pack(len(payload)) + payload)


def recv_msg(conn):
    """Receive a length-prefixed JSON message, or None if the peer closed."""
    hdr = _recvall(conn, _HDR.size)
    if hdr is None:
        return None
    (length,) = _HDR.unpack(hdr)
    data = _recvall(conn, length)
    if data is None:
        return None
    return json.loads(data.decode())


def framed_json_size(obj):
    """Size on the wire for this message: header plus payload."""
    payload = json.dumps(obj, default=_json_default).encode()
    return _HDR.size + len(payload)


def _recvall(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)
