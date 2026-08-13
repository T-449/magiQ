import matplotlib.pyplot as plt
import numpy as np

from shared import (
    DAY_IN_MIN, LIFETIME_LABELS, LIFETIME_MINUTES,
    T_CONTACT_RES_INIT, T_HANDSHAKE_INIT, apply_style, save, style_axes,
)

AGENT_COUNTS = [1, 2, 5, 10, 15]
COLORS = ["steelblue", "darkorange", "green", "red", "purple"]
MARKERS = ["o", "s", "^", "D", "v"]


def cost_per_session_ms(t_agents):
    """Contact resolution plus handshake, paid once per additional agent."""
    return (T_CONTACT_RES_INIT + T_HANDSHAKE_INIT) * t_agents


def main():
    apply_style()
    fig, ax = plt.subplots(figsize=(7.5, 5))
    x_pos = np.arange(len(LIFETIME_MINUTES))

    for t_agents, color, marker in zip(AGENT_COUNTS, COLORS, MARKERS):
        per_session = cost_per_session_ms(t_agents)
        # Cost is incurred once per A-session, so scale by sessions per day.
        overhead_s = [per_session * (DAY_IN_MIN / lifetime) / 1000
                      for lifetime in LIFETIME_MINUTES]
        ax.plot(x_pos, overhead_s, color=color, marker=marker,
                linewidth=2, markersize=6, label=str(t_agents))

    ax.set_xticks(x_pos)
    ax.set_xticklabels(LIFETIME_LABELS)
    ax.set_xlabel("A-Session Lifetime")
    ax.set_ylabel(r"Computational Overhead on $A_i$ (s)")
    ax.legend(title="Additional Agents (t)")
    style_axes(ax)

    save(fig, "oh_initiating_mas.pdf")


if __name__ == "__main__":
    main()
