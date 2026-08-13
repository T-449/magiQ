import matplotlib.pyplot as plt
import numpy as np

from rtt import distributions
from shared import T_CRYPTO, amortised_overhead, apply_style, save, style_axes

M = 100
Q_VALUES = np.arange(1, 31)
PROVIDER_REGION = "us-west-1"

REGIONS = [
    ("US-West", "blue", "us-west-1"),
    ("US-East", "red", "us-east-1"),
    ("EU", "orange", "eu-central-1"),
    ("Asia", "green", "ap-northeast-1"),
]


def main():
    rtts = distributions("p_10", "p_99", [r[2] for r in REGIONS])["data"]

    apply_style()
    fig, ax = plt.subplots(figsize=(7.5, 5))

    for label, color, region in REGIONS:
        rtt_lo, rtt_hi = rtts[region][PROVIDER_REGION]
        lower = amortised_overhead(rtt_lo, T_CRYPTO, M, Q_VALUES)
        upper = amortised_overhead(rtt_hi, T_CRYPTO, M, Q_VALUES)
        median = amortised_overhead(np.mean([rtt_lo, rtt_hi]), T_CRYPTO, M,
                                    Q_VALUES)
        ax.fill_between(Q_VALUES, lower, upper, alpha=0.2, color=color)
        ax.plot(Q_VALUES, median, color=color, linewidth=2, label=label)

    ticks = np.arange(0, 31, 10)
    ticks[0] = 1
    ax.set_xticks(ticks)
    ax.set_xlim(0, 31)
    ax.set_xlabel(r"Maximum number of requests in an A-session "
                  r"($\texttt{Q}_{\texttt{max}}$)")
    ax.set_ylabel("Amortized Protocol Overhead (ms)")
    ax.legend(title="Agent Location")
    style_axes(ax)

    print(f"T_crypto = {T_CRYPTO:.4f} ms, m = {M}")
    save(fig, "amortised_proto_oh_p_fixed.pdf")


if __name__ == "__main__":
    main()
