"""
Reporting helpers for crypto cost, bandwidth and LLM timing.
"""

_PHASE_ORDER = ["handshake", "data", "control", "other"]


def banner(text):
    print(f"\n{'=' * 60}\n  {text}\n{'=' * 60}")


def hrule(n=60, char="-"):
    print(f"    {char * n}")


def print_crypto_costs(title, local_costs, remote_costs=None,
                       local_label="Local"):
    """Print a cost table for the local side plus an optional provider side.

    Cost dicts map an operation name to a duration in seconds.
    """
    print(f"\n  +-- Crypto Cost: {title}")
    total = 0.0
    for op, dt in local_costs.items():
        print(f"  |  {op:45s} {dt * 1000:8.2f} ms")
        total += dt
    print(f"  |  {'-' * 54}")
    print(f"  |  {local_label + '-side total':45s} {total * 1000:8.2f} ms")
    if remote_costs:
        print("  |")
        remote_total = 0.0
        for op, dt in remote_costs.items():
            print(f"  |  [Provider] {op:33s} {dt * 1000:8.2f} ms")
            remote_total += dt
        print(f"  |  {'-' * 54}")
        print(f"  |  {'Provider-side total':45s} {remote_total * 1000:8.2f} ms")
        print(f"  |  {'-' * 54}")
        print(f"  |  {'TOTAL CRYPTO COST':45s} "
              f"{(total + remote_total) * 1000:8.2f} ms")
    print(f"  +{'-' * 55}")


def print_bandwidth_costs(title, phase_stats, src_label="local",
                          dst_label="remote"):
    """Print a directional byte breakdown for one exchange, keyed by phase."""
    print(f"\n  [Bandwidth] {title}")
    seen = set(phase_stats.keys())
    phases = _PHASE_ORDER + sorted(p for p in seen if p not in _PHASE_ORDER)
    for phase in phases:
        data = phase_stats.get(phase)
        if not data:
            continue
        sent = data.get("sent", 0)
        recv = data.get("recv", 0)
        print(f"  - {phase}: {src_label}->{dst_label} sent={sent} B, "
              f"{dst_label}->{src_label} sent={recv} B")


def aggregate_bandwidth(bw_list):
    """Sum a list of per-session bandwidth dicts by phase."""
    agg = {}
    for bw in bw_list:
        if not bw:
            continue
        for phase, stats in bw.items():
            bucket = agg.setdefault(phase, {"sent": 0, "recv": 0})
            bucket["sent"] += stats.get("sent", 0)
            bucket["recv"] += stats.get("recv", 0)
    return agg


def print_bandwidth_summary(title, bw_list):
    """Print aggregated per-phase bandwidth across a list of A-sessions."""
    print(f"\n  [Bandwidth] {title}")
    agg = aggregate_bandwidth(bw_list)
    g_sent = g_recv = 0
    for phase in _PHASE_ORDER + sorted(p for p in agg if p not in _PHASE_ORDER):
        s = agg.get(phase)
        if not s:
            continue
        total = s["sent"] + s["recv"]
        print(f"    {phase:12s}: sent={s['sent']:,} B  "
              f"recv={s['recv']:,} B  total={total:,} B")
        g_sent += s["sent"]
        g_recv += s["recv"]
    hrule()
    print(f"    {'TOTAL':12s}: sent={g_sent:,} B  recv={g_recv:,} B  "
          f"total={g_sent + g_recv:,} B")


def print_llm_summary(title, agents, role_fn=None):
    """Print one row per agent that made LLM calls, plus a total.

    role_fn is an optional callable(agent) -> str used to label each row.
    """
    print(f"\n  [LLM] {title}")
    total_calls = 0
    total_ms = 0.0
    for ag in agents:
        calls = getattr(ag, "_llm_total_calls", 0)
        if calls == 0:
            continue
        ms = getattr(ag, "_llm_total_sec", 0.0) * 1000
        role = f" ({role_fn(ag)})" if role_fn else ""
        print(f"    {ag.aid}{role}: {calls} calls  {ms:,.0f} ms")
        total_calls += calls
        total_ms += ms
    hrule()
    print(f"    TOTAL: {total_calls} calls  {total_ms:,.0f} ms")
