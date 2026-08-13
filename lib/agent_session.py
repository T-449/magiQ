"""
Authenticated PQ-TLS session between two agents, with per-phase byte accounting.
"""

import json
from collections import defaultdict

from lib.tls_channel import send_msg, recv_msg


def _json_default(o):
    if isinstance(o, bytes):
        return o.hex()
    raise TypeError(f"Not JSON serializable: {type(o)}")


class AgentSession:
    """Wraps an established agent-to-agent PQ-TLS connection."""

    def __init__(self, tls_conn, local_aid, remote_aid, remote_cert):
        self._conn = tls_conn
        self.local_aid = local_aid
        self.remote_aid = remote_aid
        self.remote_cert = remote_cert
        self._bw = defaultdict(
            lambda: {"sent": 0, "recv": 0, "msg_sent": 0, "msg_recv": 0})

    @staticmethod
    def _phase_from_obj(obj):
        msg_type = obj.get("type") if isinstance(obj, dict) else None
        if isinstance(msg_type, str):
            if msg_type.startswith("handshake_"):
                return "handshake"
            if msg_type.startswith("data_"):
                return "data"
        if msg_type in {"cert_exchange", "verified", "reject", "error"}:
            return "control"
        return "other"

    @staticmethod
    def _wire_size_bytes(obj):
        payload = json.dumps(obj, default=_json_default).encode()
        # tls_channel frames every message with a 4-byte length prefix.
        return 4 + len(payload)

    def send(self, obj):
        phase = self._phase_from_obj(obj)
        self._bw[phase]["sent"] += self._wire_size_bytes(obj)
        self._bw[phase]["msg_sent"] += 1
        send_msg(self._conn, obj)

    def recv(self):
        obj = recv_msg(self._conn)
        if obj is None:
            return None
        phase = self._phase_from_obj(obj)
        self._bw[phase]["recv"] += self._wire_size_bytes(obj)
        self._bw[phase]["msg_recv"] += 1
        return obj

    def bandwidth_stats(self):
        return {k: dict(v) for k, v in self._bw.items()}

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass
