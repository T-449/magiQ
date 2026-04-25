# MAGIQ: Post-Quantum Multi-Agent Demo

This project demonstrates a post-quantum, policy-aware multi-agent protocol with:

- PQ certificates and trust chain (CA, provider, users, agents)
- PQ-TLS channels for provider and agent-to-agent communication
- XMSS + ML-DSA-based identity/authentication workflow
- Two execution modes:
  - Phase A: two-agent flow
  - Phase B: multi-agent orchestrated flow

## 1. Installation

The repository includes a complete setup script that builds and installs required PQ components.

### Prerequisites

- Linux/macOS with build tools
- Conda (miniconda/anaconda/miniforge)
- Internet access for cloning/building dependencies

### Setup (recommended)

Run from project root:

```bash
./setup.sh
```

Or with a custom conda environment name:

```bash
./setup.sh <env_name>
```

What `setup.sh` does:

1. Creates/activates a conda env (Python 3.11)
2. Installs build dependencies (`cmake`, compilers, OpenSSL, etc.)
3. Builds and installs `liboqs`
4. Installs `liboqs-python`
5. Builds and installs `oqs-provider` (for PQ OpenSSL algorithms)
6. Compiles XMSS helper shared library (`lib/libxmss_helper.so`)
7. Writes activation helper script (`activate.sh`)
8. Verifies ML-DSA and XMSS capabilities

### Activate environment

If setup generated `activate.sh`:

```bash
source activate.sh
```

Or manually:

```bash
conda activate <env_name>
```

## 2. Running the Demo

Main entrypoint:

```bash
python main.py
```

Capture both stdout and stderr into a log file (recommended):

```bash
python main.py > log.txt 2>&1
```

If you only redirect stdout, Python exceptions may be missing from the log.

## 3. How to Change Runtime Behavior

Most runtime changes are done in three files:

- `config.json`
- `main.py`
- `llm.yaml`

### A) Enable/disable phases

In `config.json`, add/update:

```json
{
  "run_phase_a": true,
  "run_phase_b": true
}
```

Use `false` to skip a phase.

### B) Change tasks and workflow order

Edit task/workflow constants in `main.py`:

- `TWO_AGENT_TASKS`
- `MA_TASKS`
- `MA_WORKFLOW_SCHEDULING`
- `MA_WORKFLOW_EXPENSE`
- `MA_WORKFLOW_WRITING`

Typical modifications:

- Add/remove a step in a multi-agent workflow
- Change which agent is orchestrator/receiver
- Change task prompts or constraints

### C) Change crypto/network settings

In `config.json`:

- `algorithms.*` for XMSS/ML-DSA/hash/KEX/cipher settings
- `provider.host` and `provider.port`
- path roots under `paths.*`

### D) Change model/provider settings

In `llm.yaml`, configure:

- model name
- API base URL
- API key environment variable

### E) Change user/agent/policy data

Edit JSON files in:

- `data/users/`
- `data/agents/`
- `data/policies/`

These files control who gets registered and policy constraints (e.g., contact budgets).

## 4. Runtime-Generated Files and Directories

A run generates and updates multiple artifacts.

### Certificates

- `certs/ca/*.json`
  - CA-issued certificates for provider, users, and agents
- `certs/provider/*.json`
  - provider TLS/identity certs
- `certs/users/<user>/identity.json`
  - user identity cert material
- `certs/agents/<agent>/`
  - `app_cert.json`, `policy.json`, `registration.json`
- `certs/tls/`
  - OpenSSL-generated TLS files (`ca_cert.pem`, `server_cert.pem`, etc.)

### Keys

- `keys/ca/`
- `keys/provider/`
- `keys/users/<user>/`
- `keys/agents/<agent>/`

These include ML-DSA and XMSS key material used during registration and sessions.

### Registries

- `registries/user_registry.json`
- `registries/agent_registry.json`
- `registries/counters.json`

Used by provider-side registration state and policy counters.

### Task Output Artifacts

Current runtime behavior writes final Phase B artifacts to:

- `data/MA_NeurIPS_Expense_Report.txt`
- `MA_AI_Privacy_Blog_Post.md`

### Logs

- `log.txt` (if redirected by run command)
- Optional debug/timing output printed to terminal

