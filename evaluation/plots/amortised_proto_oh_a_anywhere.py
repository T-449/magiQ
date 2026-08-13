import matplotlib.pyplot as plt
import numpy as np

from shared import T_CRYPTO, amortised_overhead, apply_style, save, style_axes

M = 100
Q_VALUES = np.arange(1, 31)

SCENARIOS = [
    {"label": "US-West", "color": "blue", "rtt_bounds": (91.366, 196.166)},
    {"label": "US-East", "color": "red", "rtt_bounds": (69.641, 195.440)},
    {"label": "EU", "color": "orange", "rtt_bounds": (14.705, 115.546)},
    {"label": "Asia", "color": "green", "rtt_bounds": (168.332, 245.208)},
]


def main():
    apply_style()
    fig, ax = plt.subplots(figsize=(7.5, 5))

    for scenario in SCENARIOS:
        rtt_lo, rtt_hi = scenario["rtt_bounds"]
        lower = amortised_overhead(rtt_lo, T_CRYPTO, M, Q_VALUES)
        upper = amortised_overhead(rtt_hi, T_CRYPTO, M, Q_VALUES)
        median = amortised_overhead(np.mean([rtt_lo, rtt_hi]), T_CRYPTO, M,
                                    Q_VALUES)
        ax.fill_between(Q_VALUES, lower, upper, alpha=0.2,
                        color=scenario["color"])
        ax.plot(Q_VALUES, median, color=scenario["color"], linewidth=2,
                label=scenario["label"])

    ticks = np.arange(0, 31, 10)
    ticks[0] = 1
    ax.set_xticks(ticks)
    ax.set_xlim(0, 31)
    ax.set_xlabel(r"Maximum number of requests in an A-session "
                  r"($\texttt{Q}_{\texttt{max}}$)")
    ax.set_ylabel("Amortized Overhead (ms)")
    ax.legend(title="Provider Location")
    style_axes(ax)

    print(f"T_crypto = {T_CRYPTO:.4f} ms, m = {M}")
    save(fig, "amortised_proto_oh_a_anywhere.pdf")


if __name__ == "__main__":
    main()
