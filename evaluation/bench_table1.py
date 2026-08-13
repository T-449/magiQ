"""
Reproduce Table 1, the computational overhead table, on any host.


Usage:
    python evaluation/bench_table1.py [--reps N] [--rounds N] [--xmss ALGO]

"""

import argparse
import glob
import json
import os
import platform
import shutil
import ssl
import statistics
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, REPO_ROOT)

CAPTURED = []

USER_TOKEN_KEY = "XMSS sign tok^msg+Time (ICP)"

ROWS = [
    ("User Registration (User)", "User Registration", "local", None),
    ("User Registration (Provider)", "User Registration", "remote", None),
    ("Agent Registration (User)", "Agent Registration", "local", None),
    ("Agent Registration (Provider)", "Agent Registration", "remote", None),
    ("Contact Resolution (Provider)", "Contact", "remote", None),
    ("Contact Resolution (Initiating)", "Contact", "local", None),
    ("Handshake Phase (Initiating)", "Handshake Init:", "local",
     ("minus", USER_TOKEN_KEY)),
    ("Handshake Phase (User)", "Handshake Init:", "local",
     ("only", USER_TOKEN_KEY)),
    ("Handshake Phase (Receiving)", "Handshake Recv:", "local", None),
    ("Handshake Response Verify", "Handshake Resp Verify", "local", None),
    ("User-Agent Interaction (MA)", "User-Agent Interaction", "local", None),
    ("Handshake Phase (Initiating, MA)", "Handshake Init (MA)", "local", None),
    ("Handshake Phase (Receiving, MA)", "Handshake Recv (MA)", "local", None),
    ("Data Transfer (Initiating)", "@DATA_INIT", "local", None),
    ("Data Transfer (Receiving)", "Data round", "local", None),
]

KEYGEN_ROWS = [
    ("XMSS keygen (user identity)", "XMSS keygen (user)"),
    ("XMSS keygen (agent identity)", "XMSS keygen (agent)"),
]

FIXED_COST_ROWS = (
    "Contact Resolution (Provider)", "Contact Resolution (Initiating)",
    "Handshake Phase (Initiating)", "Handshake Phase (User)",
    "Handshake Phase (Receiving)", "Handshake Response Verify",
)


def _install_capture():
    """Tee every print_crypto_costs() call into CAPTURED.

    Each module did `from lib.metrics import print_crypto_costs`, which binds
    the name at import time, so every importing module has to be patched too.
    """
    import lib.metrics as metrics
    real = metrics.print_crypto_costs

    def hook(title, local_costs, remote_costs=None, local_label="Local"):
        to_ms = lambda d: {k: v * 1000.0 for k, v in d.items()}
        CAPTURED.append((title, to_ms(local_costs),
                         to_ms(remote_costs) if remote_costs else {}))
        return real(title, local_costs, remote_costs, local_label)

    metrics.print_crypto_costs = hook
    for name in ("user", "agent", "agent_ma"):
        mod = sys.modules.get(name)
        if mod is not None and hasattr(mod, "print_crypto_costs"):
            mod.print_crypto_costs = hook


def _samples_for(prefix, side, mode):
    """Collect the per-invocation totals matching a title prefix."""
    out = []
    for title, local, remote in CAPTURED:
        if not title.startswith(prefix):
            continue
        costs = local if side == "local" else remote
        if not costs:
            continue
        if mode is None:
            out.append(sum(costs.values()))
        elif mode[0] == "minus":
            out.append(sum(v for k, v in costs.items() if k != mode[1]))
        elif mode[0] == "only" and mode[1] in costs:
            out.append(costs[mode[1]])
    return out


def _pair_data_init():
    outs = [sum(c.values()) for t, c, _ in CAPTURED if t.startswith("Data req")]
    vers = [sum(c.values()) for t, c, _ in CAPTURED if t.startswith("Data resp")]
    return [outs[i] + vers[i] for i in range(min(len(outs), len(vers)))]


def _summarise(samples):
    return {
        "mean_ms": round(statistics.mean(samples), 4),
        "n": len(samples),
        "stdev_ms": round(statistics.stdev(samples), 4) if len(samples) > 1 else 0.0,
        "min_ms": round(min(samples), 4),
        "max_ms": round(max(samples), 4),
    }


def stub_app_layer(agent, size=0):
    """Replace the LLM application layer with a fixed-size responder."""
    agent._app_agent = None
    agent._handle_app_request = lambda req, reply="R" * size: {"msg": reply}


def build_phase(agent_cls, cfg):
    from ca import CertificateAuthority
    from lib.common import certs_dir, ROOT_DIR
    from lib.crypto import XMSSWrapper
    from lib.tls_channel import TLSClient, TLSServer, generate_tls_certs
    from provider import Provider
    from user import User

    xmss = XMSSWrapper()
    ca = CertificateAuthority()
    ca.init_keys()
    prov = Provider(xmss)
    prov.init_keys(ca)
    paths = generate_tls_certs(certs_dir("tls"))
    server = TLSServer(paths, prov.handle_request)
    server.start()
    client = TLSClient(paths)

    users, agents = {}, []
    pattern = os.path.join(ROOT_DIR, cfg["paths"]["data_users"], "*.json")
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            user_data = json.load(f)
        user = User(user_data=user_data, xmss=xmss, tls_client=client,
                    tls_paths=paths, agent_cls=agent_cls)
        users[user_data["uid"]] = user
        user.register(ca)
        user.register_agents(ca)
        agents.extend(user.agents.values())

    for agent in agents:
        agent._xmss = xmss
        stub_app_layer(agent)
    return xmss, server, users, agents


def drive(initiator, receiver, xmss, rounds):
    """Run one A-session with the given number of data rounds."""
    rx = {}
    thread = threading.Thread(target=receiver.run_receiver_loop, args=(rx,),
                              daemon=True)
    thread.start()
    session = initiator.start_A_session(receiver.aid, xmss)["session"]

    deadline = time.time() + 30
    while rx.get("handshake") is None and time.time() < deadline:
        time.sleep(0.02)
    if rx.get("handshake") is None:
        raise RuntimeError("handshake did not complete")

    for _ in range(rounds):
        try:
            initiator.send_data_request(session, {"msg": ""})
        except RuntimeError as e:
            print(f"    [stop] {e}")
            break

    initiator.terminate_A_session(session)
    thread.join(timeout=5)
    if rx.get("session"):
        receiver.terminate_A_session(rx["session"])


def teardown(xmss, server, agents):
    for agent in agents:
        agent.stop_listener()
    server.stop()
    try:
        xmss.cleanup()
    except Exception:
        pass
    time.sleep(0.3)


def reset_state_dirs():
    """Remove the runtime-generated key, cert and registry directories."""
    for name in ("keys", "certs", "registries"):
        shutil.rmtree(os.path.join(REPO_ROOT, name), ignore_errors=True)


def _install_classical_tls():
    """Fall back to ECDSA P-256 for the TLS transport."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import lib.tls_channel as tls_channel

    def write_key(path, key):
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))

    def write_cert(path, cert):
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def classical(cert_dir):
        os.makedirs(cert_dir, exist_ok=True)
        paths = {k: os.path.join(cert_dir, v) for k, v in {
            "ca_key": "ca_key.pem", "ca_cert": "ca_cert.pem",
            "server_key": "server_key.pem", "server_cert": "server_cert.pem",
            "client_key": "client_key.pem", "client_cert": "client_cert.pem",
        }.items()}

        now = datetime.datetime.now(datetime.timezone.utc)
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=365)

        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                "PQ-RootCA-classical")])
        ca_cert = (x509.CertificateBuilder()
                   .subject_name(ca_name).issuer_name(ca_name)
                   .public_key(ca_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(not_before).not_valid_after(not_after)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                  critical=True)
                   .add_extension(x509.KeyUsage(
                       digital_signature=True, key_cert_sign=True, crl_sign=True,
                       content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False,
                       encipher_only=False, decipher_only=False), critical=True)
                   .sign(ca_key, hashes.SHA256()))
        write_key(paths["ca_key"], ca_key)
        write_cert(paths["ca_cert"], ca_cert)

        for role, common_name in (("server", "localhost"), ("client", "pq-client")):
            key = ec.generate_private_key(ec.SECP256R1())
            builder = (x509.CertificateBuilder()
                       .subject_name(x509.Name([
                           x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
                       .issuer_name(ca_name)
                       .public_key(key.public_key())
                       .serial_number(x509.random_serial_number())
                       .not_valid_before(not_before).not_valid_after(not_after)
                       .add_extension(
                           x509.BasicConstraints(ca=False, path_length=None),
                           critical=True))
            if role == "server":
                builder = builder.add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                    critical=False)
            builder = builder.add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            write_key(paths[f"{role}_key"], key)
            write_cert(paths[f"{role}_cert"], builder.sign(ca_key, hashes.SHA256()))

        print("[bench] TLS transport: ECDSA P-256, generated in-process. "
              "Table 1 rows are unaffected, bandwidth would not be.")
        return paths

    tls_channel.generate_tls_certs = classical


def run_two_agent_phase(cfg, reps, rounds):
    from agent import Agent
    print("\n[bench] === two-agent phase ===")
    xmss, server, users, agents = build_phase(Agent, cfg)
    try:
        bob = users["bob@domain.com"].agents["bob@domain.com:agent-beta"]
        alice = users["alice@domain.com"].agents["alice@domain.com:agent-alpha"]
        for r in range(reps):
            print(f"[bench]  A-session {r + 1}/{reps}")
            drive(bob, alice, xmss, rounds)
    finally:
        teardown(xmss, server, agents)


def run_multi_agent_phase(cfg, reps, rounds):
    from agent_ma import AgentMA
    print("\n[bench] === multi-agent phase ===")
    reset_state_dirs()
    xmss, server, users, agents = build_phase(AgentMA, cfg)
    try:
        orch = users["bob@domain.com"].agents["bob@domain.com:agent-beta"]
        peers = [a for a in agents if a.aid != orch.aid]
        workflow = [{"agent_aid": p.aid, "instruction": "bench"} for p in peers]
        sessions = max(1, reps // 2)
        for r in range(sessions):
            print(f"[bench]  C-session {r + 1}/{sessions}")
            orch.run_user_agent_interaction("bench task", workflow, xmss)
            for i, peer in enumerate(peers):
                orch._task_state["current_step"] = i
                drive(orch, peer, xmss, rounds)
            orch.reset_task_state()
    finally:
        teardown(xmss, server, agents)


def collect_results(cfg, args, wall_s):
    result = {
        "meta": {
            "python": platform.python_version(),
            "openssl": ssl.OPENSSL_VERSION,
            "xmss": cfg["algorithms"]["xmss"],
            "mldsa": cfg["algorithms"]["mldsa"],
            "reps": args.reps,
            "rounds": args.rounds,
            "wall_s": round(wall_s, 1),
        },
        "rows": {},
    }

    for label, prefix, side, mode in ROWS:
        samples = (_pair_data_init() if prefix == "@DATA_INIT"
                   else _samples_for(prefix, side, mode))
        result["rows"][label] = _summarise(samples) if samples else None

    for key, label in KEYGEN_ROWS:
        samples = [costs[key] for _, costs, _ in CAPTURED if key in costs]
        if samples:
            result["rows"][label] = _summarise(samples)

    return result


def print_table(result):
    print("\n" + "=" * 74)
    print(f"  TABLE 1  ({result['meta']['xmss']})")
    print("=" * 74)
    print(f"  {'row':44}{'mean ms':>11}{'sd':>9}{'n':>5}")
    print("  " + "-" * 68)

    labels = [label for label, _, _, _ in ROWS] + [l for _, l in KEYGEN_ROWS]
    for label in labels:
        row = result["rows"].get(label)
        if row is None:
            print(f"  {label:44}{'--':>11}")
        else:
            print(f"  {label:44}{row['mean_ms']:>11.2f}"
                  f"{row['stdev_ms']:>9.2f}{row['n']:>5}")

    fixed = sum(result["rows"][k]["mean_ms"] for k in FIXED_COST_ROWS
                if result["rows"].get(k))
    per_interaction = (result["rows"].get("Data Transfer (Initiating)")
                       or {}).get("mean_ms", 0)
    print(f"\n  t_crypto = fixed {fixed:.2f} ms + {per_interaction:.2f} x 100 "
          f"= {fixed + per_interaction * 100:.2f} ms")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reps", type=int, default=8,
                        help="A-sessions to drive per phase")
    parser.add_argument("--rounds", type=int, default=10,
                        help="data-transfer rounds per session")
    parser.add_argument("--xmss", default=None,
                        help="override the config.json XMSS algorithm")
    parser.add_argument("--tag", default="",
                        help="optional label appended to the output filename")
    parser.add_argument("--classical-tls", action="store_true",
                        help="use ECDSA P-256 for the TLS transport when the "
                             "local OpenSSL lacks ML-DSA")
    args = parser.parse_args()

    if args.xmss:
        config_path = os.path.join(REPO_ROOT, "config.json")
        with open(config_path) as f:
            cfg_file = json.load(f)
        cfg_file["algorithms"]["xmss"] = args.xmss
        with open(config_path, "w") as f:
            json.dump(cfg_file, f, indent=4)
        print(f"[bench] config.json xmss -> {args.xmss}")

    reset_state_dirs()

    from lib.common import load_config
    cfg = load_config()
    import agent, agent_ma, user 
    _install_capture()
    if args.classical_tls:
        _install_classical_tls()

    t0 = time.time()
    run_two_agent_phase(cfg, args.reps, args.rounds)
    run_multi_agent_phase(cfg, args.reps, args.rounds)

    result = collect_results(cfg, args, time.time() - t0)
    name = f"table1_{args.tag}.json" if args.tag else "table1.json"
    out_path = os.path.join(HERE, name)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print_table(result)
    print(f"\n  wrote {out_path}")


if __name__ == "__main__":
    main()
