## Quick start

```bash
./setup.sh              # builds liboqs, the XMSS helper, and a local venv
source activate.sh
python main.py
```

Everything `setup.sh` builds goes into `./.venv` and `./.build`. Nothing is
written outside the repository and sudo is never used.

Prerequisites:

| Platform | Install |
|----------|---------|
| macOS | `xcode-select --install` and `brew install openssl@3 python@3.13` |
| Ubuntu / Debian | `sudo apt install build-essential git python3-venv libssl-dev` |

**OpenSSL 3.5 or newer is required**, in two places: the `openssl` command line
that mints the ML-DSA-65 certificates, and the OpenSSL that Python's `ssl`
module is linked against. Agent-to-agent sessions are PQ-mTLS, so an
interpreter linked against an older OpenSSL cannot complete the handshake.

`setup.sh` searches for a pair that satisfies both and stops with instructions
if it cannot find one. It reports what it picked:

```
[INFO]  python   /opt/homebrew/bin/python3  (3.13.2, OpenSSL 3.6.2 7 Apr 2026)
[INFO]  openssl  /opt/homebrew/opt/openssl@3/bin/openssl  (OpenSSL 3.6.2)
```

Override the search with `PYTHON=/path/to/python3 OPENSSL=/path/to/openssl
./setup.sh`. This matters if a conda or distribution Python comes first on your
PATH, which is common and usually links an older OpenSSL. `activate.sh` puts
the selected `openssl` first on PATH for the same reason.

Ubuntu 24.04 ships OpenSSL 3.0, so it needs a newer one plus a Python built
against it.

Before running `main.py`, point `llm.yaml` at a model. `setup.sh` creates it
from `llm.example.yaml`.

To capture a full run:

```bash
python main.py > run.log 2>&1
```

## What a run does

`config.json` selects the phases. The default is Phase B only.

**Phase A, two agents.** Bob's agent and Alice's agent register, open one
A-session, and work through three tasks: scheduling a meeting, assembling an
expense report, and co-writing a blog post.

**Phase B, multi-agent.** Bob's agent orchestrates five receiving agents over a
static workflow. It commits up front to one hash chain and one time slice per
step, has its user sign both Merkle roots once, then opens one A-session per
step. Each receiver verifies that single token plus a membership proof for the
budget it was given. The same three tasks run, now six-way.

The scheduling task has a unique correct answer by construction. The six agent
personas in `agents_llm.py` intersect in exactly one 30-minute window,
16:00-16:30, so a successful run has to find it.

Each phase prints per-operation crypto costs, per-phase byte counts, and LLM
call totals.

## Reproducing the paper results

### Table 1, computational overhead

No API key, no LLM and no network access beyond cloning liboqs. Table 1 is pure
crypto, so the application layer is stubbed with a fixed-size responder.

```bash
python evaluation/bench_table1.py                          # fast, uses config.json
python evaluation/bench_table1.py --xmss XMSS-SHA2_16_256  # numbers in the paper
```

Results are written to `evaluation/table1.json` and printed as a table. Every evaluation script resolves its own paths, so it does not matter
which directory you run it from.

`XMSS-SHA2_16_256` generates 13 keys per phase across two phases at roughly 36 s per key on a Threadripper PRO 5955WX.

Registration rows are sampled once per user and agent, so `n=6` there whatever
`--reps` is set to. 

If your Python links against an OpenSSL older than 3.5 and oqs-provider is not
available, pass `--classical-tls`. The transport falls back to ECDSA P-256.

Two side effects to know about: `--xmss` rewrites `algorithms.xmss` in
`config.json` in place, and every run deletes and regenerates `keys/`, `certs/`
and `registries/`, so do not start a benchmark while `main.py` is running.

### Bandwidth

```bash
python evaluation/bw_harness.py          # 10 rounds, empty payload, 1 repetition
python evaluation/bw_harness.py 10 0 4   # rounds, payload chars, repetitions
```

Writes `evaluation/bw_results.json`. Byte counts are machine-independent, so
these should match exactly across hosts. They are only meaningful over full
PQ-mTLS.

### Plots

```bash
python evaluation/plots/amortised_proto_oh_a_anywhere.py
python evaluation/plots/amortised_proto_oh_p_fixed.py  
python evaluation/plots/oh_initiating_mas.py
python evaluation/plots/provider_overhead_session.py
```

Each writes a PDF into `evaluation/plots/`.

The per-phase costs the plots build on are read from a benchmark run. If a
`table1.json` is present in `evaluation/`. Run `bench_table1.py` first and
the plots follow automatically, with no editing.

With no benchmark output present, the published measurements in
`evaluation/plots/shared.py` are used instead. 

A run that is missing any row the plots need falls back to the published values
in full rather than mixing the two. Set `MAGIQ_TABLE1` to a path to pin a specific result file.

The two amortised-overhead plots use different latency sources, because they
answer different questions:

- `amortised_proto_oh_p_fixed.py` fixes the provider at us-west-1 and varies the
  agent across four AWS regions, so it pulls inter-region latencies live from
  cloudping.co and needs network access.
- `amortised_proto_oh_a_anywhere.py` puts the agent anywhere on the internet,
  which is a whole-topology question that AWS region data cannot answer. Its
  bounds are CAIDA Ark constants in the script, since Ark is distributed as bulk
  datasets rather than a query endpoint. They are inherited from the original
  measurements and are not reproduced by anything in this repository.

Axis labels render through LaTeX when a `latex` binary is on PATH and fall back
to matplotlib's own text rendering otherwise, so no TeX install is required.

## Configuration

**`config.json`** controls crypto and networking.

| Key | Meaning |
|-----|---------|
| `algorithms.xmss` | XMSS instance. `_10_256` is fast, `_16_256` is what the paper uses |
| `algorithms.mldsa`, `kex`, `cipher_suite` | PQ-mTLS parameters |
| `provider.host`, `provider.port` | Where the provider listens |
| `paths.*` | Roots for generated keys, certs and registries |
| `run_phase_a`, `run_phase_b` | Which phases `main.py` runs |
| `debug` | Verbose per-operation logging |

**`demo.py`** holds the scenario: task text, which agent orchestrates, and the
workflow order, as `TWO_AGENT_TASKS` and `MA_TASKS`. Edit these to add or remove
a step, change the orchestrator, or reword a task. It is pure data and imports
nothing, so it cannot affect how the protocol runs.

**`main.py`** is the entry point and knows nothing about the scenario. It sets
each phase up, runs whatever tasks it is handed, and tears the phase down. To
run something other than the shipped demo, write a module exposing the same two
lists and call `main.run(two_agent_tasks, ma_tasks)`:

```python
{"name": ..., "task": ..., "initiator": aid, "receiver": aid}
{"name": ..., "task": ..., "orchestrator": aid, "workflow": [...]}
```

**`data/users/*.json`** defines who registers, each with their agents, ports
and tool categories. **`data/policies/*.json`** defines each agent's contact
policy: `allowed_contacts` with a per-peer budget `Q`, the initiator policy
`icp` (`m` chains of length `n_prime`, total budget `Q_tot`, total time
`delta_tot_sec`), and the responder policy `rcp` (`Q` messages within
`delta_sec`).

## Layout

```
main.py                      Entry point, phase setup and task execution
demo.py                      Example scenario
ca.py                        Certificate authority
provider.py                  Trust provider: registration, contact, budgets
user.py                      Key custodian, agent registration, token issuance
agent.py                     Agent state, PQ-TLS, two-agent A-session protocol
agent_ma.py                  Multi-agent C-session on top of Agent
agents_llm.py                AutoGen application agents and their tools
data/                        User definitions and contact policies

lib/common.py                Config, paths, IO, hashing, chains, Merkle trees
lib/crypto.py                XMSS and ML-DSA wrappers, certificates
lib/tls_channel.py           PQ-mTLS transport and framed JSON messaging
lib/agent_session.py         Agent session with per-phase byte accounting
lib/metrics.py               Cost, bandwidth and LLM reporting
lib/xmss_helper.c            C shim over the liboqs stateful signature API

evaluation/bench_table1.py   Table 1, computational overhead
evaluation/bw_harness.py     Bandwidth measurement
evaluation/plots/            Paper figures, constants in plots/shared.py
```

Nothing under `evaluation/` is imported by the protocol itself. Each script
adds the repository root to `sys.path` and resolves its own output paths, so it
can be run from any directory and deleted without affecting a normal run.

A run generates `keys/`, `certs/` and `registries/`, recreated from scratch each
time, plus `output/` for anything the agents write: the expense report, the
merged blog post and the per-step handoff artifacts. All four are git-ignored.

Everything the agents produce is confined to `output/`.
