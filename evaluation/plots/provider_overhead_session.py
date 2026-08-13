import matplotlib.pyplot as plt
import numpy as np

from shared import (
    DAY_IN_MIN, LIFETIME_LABELS, LIFETIME_MINUTES,
    T_CONTACT_RES_PROVIDER, apply_style, save, style_axes,
)

AGENT_COUNTS = [1, 10, 100]
COLORS = ["steelblue", "darkorange", "green"]
MARKERS = ["o", "s", "^"]


def overhead_sec(n_agents, lifetime_min):
    """One contact resolution per agent per A-session, summed over a day."""
    tokens_per_day = n_agents * (DAY_IN_MIN / lifetime_min)
    return (tokens_per_day * T_CONTACT_RES_PROVIDER) / 1000


def main():
    apply_style()
    fig, ax = plt.subplots(figsize=(7.5, 5))
    x_pos = np.arange(len(LIFETIME_MINUTES))

    for n_agents, color, marker in zip(AGENT_COUNTS, COLORS, MARKERS):
        overhead = [overhead_sec(n_agents, lifetime)
                    for lifetime in LIFETIME_MINUTES]
        ax.plot(x_pos, overhead, label=str(n_agents), color=color,
                marker=marker, linewidth=2, markersize=7)

    ax.set_xticks(x_pos)
    ax.set_xticklabels(LIFETIME_LABELS)
    ax.set_xlabel("A-Session Lifetime")
    ax.set_ylabel("Computational Overhead on Provider (s)")
    ax.yaxis.set_label_coords(-0.09, 0.45)
    ax.legend(title="Initiating Agents")
    style_axes(ax)

    save(fig, "provider_overhead_session.pdf")


if __name__ == "__main__":
    main()
