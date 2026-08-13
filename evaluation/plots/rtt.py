import requests

API_URL = "https://www.cloudping.co/api/latencies"


def fetch_rtt(percentile="p_98", timeframe="1Y"):
    """Fetch the inter-region latency matrix for one percentile."""
    response = requests.get(API_URL,
                            params={"percentile": percentile,
                                    "timeframe": timeframe},
                            timeout=30)
    response.raise_for_status()
    return response.json()


def filter_locations(data, locations):
    """Keep only the source and destination regions of interest."""
    filtered = {"metadata": data["metadata"], "data": {}}
    for src, destinations in data["data"].items():
        if src not in locations:
            continue
        for dst, latency in destinations.items():
            if dst in locations:
                filtered["data"].setdefault(src, {})[dst] = latency
    return filtered


def merge_bounds(lower, upper):
    """Pair the two percentile matrices into (low, high) tuples."""
    merged = {"metadata": dict(lower["metadata"]), "data": {}}
    merged["metadata"]["percentile"] = [lower["metadata"]["percentile"],
                                        upper["metadata"]["percentile"]]
    for src, destinations in lower["data"].items():
        merged["data"][src] = {dst: (latency, upper["data"][src][dst])
                               for dst, latency in destinations.items()}
    return merged


def distributions(lower_percentile, upper_percentile, locations):
    """Return an RTT band between the two given percentiles."""
    lower = filter_locations(fetch_rtt(percentile=lower_percentile), locations)
    upper = filter_locations(fetch_rtt(percentile=upper_percentile), locations)
    return merge_bounds(lower, upper)
