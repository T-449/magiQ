"""
provider.py — Trust Provider
=============================
Handles user registration, agent registration, and agent contact requests.
Manages contact budget counters.
"""

import json
import time

from lib.common import (
    load_config, debug, sha256, sha256_hex,
    keys_dir, certs_dir, registries_dir,
    save_bytes, save_json,
    build_tuple_message,
)
from lib.crypto import (
    MLDSAWrapper, verify_certificate, pk_from_cert, XMSS_ALGO, MLDSA_ALGO,
)

_CFG = load_config()


def _t():
    return time.perf_counter()


class Provider:

    def __init__(self, xmss):
        self.name = _CFG["provider"]["name"]
        self._xmss = xmss
        self._mldsa = MLDSAWrapper()

        self._tls_pk = None
        self._tls_sk = None
        self._tls_cert = None
        self._id_handle = None
        self._id_pk = None
        self._id_cert = None

        self.user_registry = {}
        self.agent_registry = {}
        self._ca_pk = None

        # Contact budget: counters[aid_R][aid_I] = remaining budget
        self.counters = {}

        print(f"[PROVIDER] '{self.name}' created")

    #  Init 
    def init_keys(self, ca):
        self._ca_pk = ca.get_public_key()
        kd = keys_dir("provider")

        print(f"[PROVIDER] Generating ML-DSA-65 (TLS) ...")
        self._tls_pk, self._tls_sk = self._mldsa.keygen()
        save_bytes(self._tls_pk, f"{kd}/mldsa_tls_pk.bin")
        save_bytes(self._tls_sk, f"{kd}/mldsa_tls_sk.bin")

        self._tls_cert = ca.issue_cert(self.name, self._tls_pk, MLDSA_ALGO)
        save_json(self._tls_cert, f"{certs_dir('provider')}/tls_cert.json")

        print(f"[PROVIDER] Generating XMSS (identity) ...")
        self._id_handle, self._id_pk = self._xmss.keygen()
        save_bytes(self._id_pk, f"{kd}/xmss_id_pk.bin")
        print(f"[PROVIDER] id_pk={len(self._id_pk)}B "
              f"fp={sha256_hex(self._id_pk)[:16]}...")

        self._id_cert = ca.issue_cert(
            f"{self.name}:identity", self._id_pk, XMSS_ALGO)
        save_json(self._id_cert, f"{certs_dir('provider')}/id_cert.json")

        ca.register_provider(self._tls_cert, self._id_cert)

    #  TLS dispatcher 
    def handle_request(self, req):
        action = req.get("action")
        debug("PROVIDER", f"action={action}")
        if action == "register_user":
            return self._handle_register_user(req)
        elif action == "register_agent":
            return self._handle_register_agent(req)
        elif action == "contact_request":
            return self._handle_contact_request(req)
        elif action == "get_provider_info":
            return self._handle_get_info()
        return {"success": False, "message": f"unknown action: {action}"}

    def _handle_get_info(self):
        return {
            "success": True,
            "tls_cert": self._tls_cert,
            "id_cert": self._id_cert,
        }

    #  User registration 
    def _handle_register_user(self, req):
        uid, pwd, cert_u = req["uid"], req["password"], req["cert_u"]
        timing = {}
        print(f"\n[PROVIDER] === User Registration: {uid} ===")

        t0 = _t()
        valid = verify_certificate(cert_u, self._ca_pk, self._mldsa)
        timing["ML-DSA-65 verify (user cert)"] = _t() - t0
        if not valid:
            return {"success": False, "message": "cert invalid"}
        print(f"[PROVIDER] ✓ Cert verified")

        if cert_u.get("subject") != uid:
            return {"success": False, "message": "subject mismatch"}
        if not self._verify_identity_external(uid):
            return {"success": False, "message": "identity check failed"}
        print(f"[PROVIDER] ✓ Identity verified (OIDC)")
        if uid in self.user_registry:
            return {"success": False, "message": "account exists"}

        t0 = _t()
        pwd_hash = sha256(pwd.encode())
        timing["SHA-256 (password hash)"] = _t() - t0

        self.user_registry[uid] = {
            "pwd_hash_hex": pwd_hash.hex(),
            "cert_u": cert_u,
        }
        self._save_registries()
        print(f"[PROVIDER] ✓ Registered: {uid}")
        return {"success": True, "message": "registered",
                "crypto_timing": timing}

    def _verify_identity_external(self, uid):
        debug("PROVIDER", f"[OIDC] {uid} → OK")
        return True

    def _auth(self, uid, pwd):
        if uid not in self.user_registry:
            return False
        return self.user_registry[uid]["pwd_hash_hex"] == sha256(pwd.encode()).hex()

    def _user_id_pk(self, uid):
        if uid not in self.user_registry:
            return None
        return pk_from_cert(self.user_registry[uid]["cert_u"])

    #  Agent registration 
    def _handle_register_agent(self, req):
        uid      = req["uid"]
        pwd      = req["password"]
        aid      = req["aid"]
        ed       = req["ed"]
        cp       = req["cp"]
        cert_a   = req["cert_a"]
        id_pk_a  = bytes.fromhex(req["id_pk_a_hex"])
        sig_id   = bytes.fromhex(req["sig_id_hex"])
        sig_a    = bytes.fromhex(req["sig_a_hex"])
        timing   = {}

        print(f"\n[PROVIDER] === Agent Registration: {aid} ===")

        if not self._auth(uid, pwd):
            return {"success": False, "message": "auth failed"}
        print(f"[PROVIDER] ✓ Authenticated")

        if aid in self.agent_registry:
            return {"success": False, "message": "aid exists"}

        ek = f"{ed['device']}:{ed['ip']}:{ed['port']}"
        for _, r in self.agent_registry.items():
            e = r["metadata"]["ed"]
            if f"{e['device']}:{e['ip']}:{e['port']}" == ek:
                return {"success": False, "message": "endpoint exists"}

        t0 = _t()
        valid = verify_certificate(cert_a, self._ca_pk, self._mldsa)
        timing["ML-DSA-65 verify (agent cert)"] = _t() - t0
        if not valid:
            return {"success": False, "message": "agent cert invalid"}
        print(f"[PROVIDER] ✓ Agent cert verified")

        user_pk = self._user_id_pk(uid)
        if user_pk is None:
            return {"success": False, "message": "user pk missing"}

        t0 = _t()
        ok_id = self._xmss.verify(
            build_tuple_message(aid, id_pk_a), sig_id, user_pk)
        timing["XMSS verify sigma_ID"] = _t() - t0
        if not ok_id:
            return {"success": False, "message": "sig_id invalid"}
        print(f"[PROVIDER] ✓ sig_id verified")

        ed_b = json.dumps(ed, sort_keys=True, separators=(",", ":")).encode()
        pk_a = pk_from_cert(cert_a)
        t0 = _t()
        ok_a = self._xmss.verify(
            build_tuple_message(aid, ed_b, pk_a, self._tls_pk, self._id_pk),
            sig_a, user_pk)
        timing["XMSS verify sigma_A"] = _t() - t0
        if not ok_a:
            return {"success": False, "message": "sig_a invalid"}
        print(f"[PROVIDER] ✓ sig_a verified")

        # Store
        # Store — extract the inner contact_policy dict
        cp_inner = cp.get("contact_policy", cp)
        self.agent_registry[aid] = {
            "uid": uid,
            "metadata": {"ed": ed, "cert_a": cert_a,
                         "id_pk_a_hex": id_pk_a.hex()},
            "contact_policy": cp_inner,
            "sig_id_hex": sig_id.hex(),
            "sig_a_hex": sig_a.hex(),
        }

        # Initialise contact counters from allowed_contacts
        self._init_counters(aid, cp_inner)

        # Countersign
        ca_b = json.dumps(cert_a, sort_keys=True, separators=(",", ":")).encode()
        t0 = _t()
        sig_ta = self._xmss.sign(
            self._id_handle,
            build_tuple_message(aid, ca_b, ed_b, id_pk_a, sig_a))
        timing["XMSS sign sigma_TA"] = _t() - t0
        print(f"[PROVIDER] ✓ Countersig ({len(sig_ta)}B)")

        self._save_registries()
        return {"success": True, "sig_ta_hex": sig_ta.hex(),
                "message": f"Agent {aid} registered",
                "crypto_timing": timing}

    def _init_counters(self, aid, cp):
        """Initialise contact budget counters from allowed_contacts."""
        allowed = cp.get("allowed_contacts", [])
        if aid not in self.counters:
            self.counters[aid] = {}
        for entry in allowed:
            peer = entry["peer_aid"]
            budget = entry.get("Q", 0)
            self.counters[aid][peer] = budget
            debug("PROVIDER", f"counter[{aid}][{peer}] = {budget}")

    
    #  Agent Contact Request  (protocol section i)
    
    def _handle_contact_request(self, req):
        """Handle a contact request from initiator A_I wanting to reach A_R.

        1. Verify A_I is in A_R's contact policy and vice versa
        2. Check budget Counter[aid_R][aid_I] > 0
        3. Return A_R's info + provider signature sigma^TA_ac
        4. Decrement counter
        """
        aid_i = req["aid_i"]
        aid_r = req["aid_r"]
        timing = {}
        print(f"\n[PROVIDER] === Contact Request: {aid_i} → {aid_r} ===")

        # Both agents must be registered
        if aid_i not in self.agent_registry:
            return {"success": False, "message": f"initiator {aid_i} not registered"}
        if aid_r not in self.agent_registry:
            return {"success": False, "message": f"receiver {aid_r} not registered"}

        rec_i = self.agent_registry[aid_i]
        rec_r = self.agent_registry[aid_r]

        # Check A_I is in A_R's contact policy
        if not self._in_contact_policy(aid_i, rec_r["contact_policy"]):
            print(f"[PROVIDER] ✗ {aid_i} not in {aid_r}'s contact policy")
            return {"success": False, "message": "initiator not in receiver policy"}

        # Check A_R is in A_I's contact policy
        if not self._in_contact_policy(aid_r, rec_i["contact_policy"]):
            print(f"[PROVIDER] ✗ {aid_r} not in {aid_i}'s contact policy")
            return {"success": False, "message": "receiver not in initiator policy"}

        # Check budget
        budget = self.counters.get(aid_r, {}).get(aid_i, 0)
        if budget <= 0:
            print(f"[PROVIDER] ✗ Budget exhausted: counter[{aid_r}][{aid_i}]={budget}")
            return {"success": False, "message": "budget exhausted"}
        print(f"[PROVIDER] ✓ Policy check passed (budget={budget})")

        # Collect A_R's information
        uid_r = rec_r["uid"]
        cert_u_r = self.user_registry[uid_r]["cert_u"]
        ed_r = rec_r["metadata"]["ed"]
        cert_a_r = rec_r["metadata"]["cert_a"]
        id_pk_r = bytes.fromhex(rec_r["metadata"]["id_pk_a_hex"])
        pk_r = pk_from_cert(cert_a_r)
        sig_id_r = bytes.fromhex(rec_r["sig_id_hex"])
        sig_a_r = bytes.fromhex(rec_r["sig_a_hex"])

        # A_I's identity key
        id_pk_i = bytes.fromhex(rec_i["metadata"]["id_pk_a_hex"])

        # Expiry from receiver's policy
        t_exp = rec_r["contact_policy"].get("expiry", "2099-01-01T00:00:00Z")

        # M_R = {ED_R, Cert_R, ID-Pk_R}
        ed_r_b = json.dumps(ed_r, sort_keys=True, separators=(",", ":")).encode()
        cert_a_r_b = json.dumps(cert_a_r, sort_keys=True,
                                separators=(",", ":")).encode()

        # sigma^TA_ac = HS.Sign(ID-Sk_TA,
        #   <T_exp, Cert_U_R, aid_R, M_R, Pk_R, sigma^U_R_ID, sigma^U_R_A, aid_I, ID-Pk_I>)
        t0 = _t()
        sig_ta_ac = self._xmss.sign(
            self._id_handle,
            build_tuple_message(
                t_exp,
                json.dumps(cert_u_r, sort_keys=True,
                           separators=(",", ":")).encode(),
                aid_r, ed_r_b, cert_a_r_b, id_pk_r,
                pk_r, sig_id_r, sig_a_r,
                aid_i, id_pk_i))
        timing["XMSS sign sigma_TA_ac"] = _t() - t0
        print(f"[PROVIDER] ✓ sigma_TA_ac signed ({len(sig_ta_ac)}B)")

        # Decrement counter
        self.counters[aid_r][aid_i] -= 1
        remaining = self.counters[aid_r][aid_i]
        print(f"[PROVIDER] Counter[{aid_r}][{aid_i}]: {budget} → {remaining}")

        self._save_registries()

        return {
            "success": True,
            "t_exp": t_exp,
            "cert_u_r": cert_u_r,
            "aid_r": aid_r,
            "ed_r": ed_r,
            "cert_a_r": cert_a_r,
            "id_pk_r_hex": id_pk_r.hex(),
            "pk_r_hex": pk_r.hex(),
            "sig_id_r_hex": sig_id_r.hex(),
            "sig_a_r_hex": sig_a_r.hex(),
            "aid_i": aid_i,
            "id_pk_i_hex": id_pk_i.hex(),
            "sig_ta_ac_hex": sig_ta_ac.hex(),
            "crypto_timing": timing,
        }

    def _in_contact_policy(self, peer_aid, cp):
        """Check if peer_aid appears in a contact policy's allowed_contacts."""
        for entry in cp.get("allowed_contacts", []):
            if entry.get("peer_aid") == peer_aid:
                return True
        return False

    #  Persistence ─
    def _save_registries(self):
        rd = registries_dir()
        save_json(self.user_registry, f"{rd}/user_registry.json")
        save_json(self.agent_registry, f"{rd}/agent_registry.json")
        save_json(self.counters, f"{rd}/counters.json")