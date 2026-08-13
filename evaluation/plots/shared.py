import glob
import json
import os
import shutil
from math import ceil

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

HERE = os.path.dirname(os.path.abspath(__file__))
EVALUATION_DIR = os.path.dirname(HERE)

INTERACTION_BUDGET = 100

PUBLISHED_COSTS = {
    "Contact Resolution (Provider)": 2.66,
    "Contact Resolution (Initiating)": 1.82,
    "Handshake Phase (Initiating)": 3.68,
    "Handshake Phase (User)": 3.38,
    "Handshake Phase (Receiving)": 3.03,
    "Handshake Response Verify": 0.47,
    "Data Transfer (Initiating)": 0.03,
}

PUBLISHED_SOURCE = "published measurements (5955WX, XMSS-SHA2_16_256)"


def _newest_benchmark():
    override = os.environ.get("MAGIQ_TABLE1")
    if override:
        return override if os.path.exists(override) else None
    results = glob.glob(os.path.join(EVALUATION_DIR, "table1*.json"))
    return max(results, key=os.path.getmtime) if results else None


def load_costs():
    path = _newest_benchmark()
    if path is None:
        return dict(PUBLISHED_COSTS), PUBLISHED_SOURCE

    with open(path) as f:
        result = json.load(f)
    rows = result.get("rows", {})

    costs = {}
    for label in PUBLISHED_COSTS:
        row = rows.get(label)
        if not row or row.get("mean_ms") is None:
            return (dict(PUBLISHED_COSTS),
                    f"{PUBLISHED_SOURCE}, because {os.path.basename(path)} "
                    f"is missing the row '{label}'")
        costs[label] = row["mean_ms"]

    meta = result.get("meta", {})
    source = f"{os.path.basename(path)} ({meta.get('xmss', 'unknown XMSS')})"
    return costs, source


COSTS, COSTS_SOURCE = load_costs()

T_CONTACT_RES_PROVIDER = COSTS["Contact Resolution (Provider)"]
T_CONTACT_RES_INIT = COSTS["Contact Resolution (Initiating)"]
T_HANDSHAKE_INIT = COSTS["Handshake Phase (Initiating)"]
T_HANDSHAKE_USER = COSTS["Handshake Phase (User)"]
T_HANDSHAKE_RECV = COSTS["Handshake Phase (Receiving)"]
T_HANDSHAKE_RESP_VER = COSTS["Handshake Response Verify"]
T_DATA_TRANSFER = COSTS["Data Transfer (Initiating)"]

T_CRYPTO = (
    T_CONTACT_RES_PROVIDER
    + T_CONTACT_RES_INIT
    + T_HANDSHAKE_INIT
    + T_HANDSHAKE_USER
    + T_HANDSHAKE_RECV
    + T_HANDSHAKE_RESP_VER
    + T_DATA_TRANSFER * INTERACTION_BUDGET
)

DAY_IN_MIN = 24 * 60

LIFETIME_LABELS = ["1 min", "3 min", "6 min", "12 min", "1 hr", "8 hrs", "1 day"]
LIFETIME_MINUTES = [1, 3, 6, 12, 60, 480, 1440]


def amortised_overhead(rtt, t_crypto, m, q_max_values):
    """Protocol overhead per interaction, in milliseconds.

    C_proto is (RTT(agent, provider) + t_crypto) * ceil(m / Q_max), and this
    returns C_proto / m. RTT(agent, user) is zero, since the user is colocated
    with the initiating agent.
    """
    return np.array([((rtt + t_crypto) * ceil(m / q)) / m
                     for q in q_max_values])


def apply_style():
    """Apply the shared figure style, using LaTeX text only if available."""
    sns.set_theme(style="whitegrid")
    plt.rcParams["text.usetex"] = shutil.which("latex") is not None
    plt.rcParams.update({
        "font.size": 17,
        "axes.labelsize": 20,
        "axes.titlesize": 16,
        "legend.title_fontsize": 15,
        "legend.fontsize": 15,
        "xtick.labelsize": 15,
        "ytick.labelsize": 15,
    })


def style_axes(ax):
    """Apply the shared axis treatment: ticks on two sides, no grid."""
    ax.tick_params(axis="both", which="both", bottom=True, left=True,
                   top=False, right=False)
    ax.grid(False)
    ax.set_ylim(bottom=0)


def save(fig, filename):
    """Write a figure next to these scripts, whatever the current directory."""
    path = os.path.join(HERE, filename)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Costs from: {COSTS_SOURCE}")
    print(f"Saved {path}")
