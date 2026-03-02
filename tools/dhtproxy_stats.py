#!/usr/bin/env python3
"""Collect and aggregate statistics from DHT proxy servers."""

import asyncio
import json
import sys
import time
from typing import Dict, Any

import aiohttp


# Configuration
START_PORT = 80
END_PORT = 101
HOST = "localhost"
OUTPUT_FILE = "stats_proxy_total"
REQUEST_TIMEOUT = 20  # seconds


def initialize_stats(timestamp: float) -> Dict[str, Any]:
    """Initialize the stats dictionary with zero values."""
    return {
        "users": 0,
        "pushListenersCount": 0,
        "listenCount": 0,
        "totalListeners": 0,
        "totalPermanentPuts": 0,
        "timestamp": timestamp,
        "local_storage_size": 0,
        "local_storage_values": 0,
        "storage_size": 0,
        "storage_values": 0
    }


async def get_proxy_stats(session: aiohttp.ClientSession, port: int) -> Dict[str, Any]:
    url = f"http://{HOST}:{port}/node/stats"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as response:
            response.raise_for_status()
            return await response.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Error fetching stats from proxy {port}: {e}", file=sys.stderr)
        return None


def extract_stat(data: Dict[str, Any], key: str, default: int = 0) -> int:
    try:
        return int(data.get(key, default))
    except (ValueError, TypeError):
        return default


def aggregate_proxy_stats(result: Dict[str, Any], stats_total: Dict[str, Any]):
    """Aggregate statistics from a single proxy into the total."""
    # Calculate users from putCount (divide by 2)
    put_count = extract_stat(result, "putCount")
    stats_total["users"] += put_count // 2

    # Aggregate listener counts
    push_listeners = extract_stat(result, "pushListenersCount")
    listen_count = extract_stat(result, "listenCount")

    stats_total["pushListenersCount"] += push_listeners
    stats_total["listenCount"] += listen_count
    stats_total["totalListeners"] += push_listeners + listen_count
    stats_total["totalPermanentPuts"] += extract_stat(
        result, "totalPermanentPuts")

    # Aggregate storage statistics from nodeInfo
    node_info = result.get("nodeInfo", {})
    stats_total["local_storage_size"] += extract_stat(
        node_info, "local_storage_size")
    stats_total["local_storage_values"] += extract_stat(
        node_info, "local_storage_values")
    stats_total["storage_size"] += extract_stat(node_info, "storage_size")
    stats_total["storage_values"] += extract_stat(node_info, "storage_values")


async def collect_all_stats() -> Dict[str, Any]:
    timestamp = time.time()
    stats_total = initialize_stats(timestamp)

    async with aiohttp.ClientSession() as session:
        # Create tasks for all proxy requests in parallel
        tasks = []
        for port in range(START_PORT, END_PORT):
            tasks.append(get_proxy_stats(session, port))

        # Wait for all requests to complete
        print(f"Collecting stats from {len(tasks)} proxies in parallel...")
        results = await asyncio.gather(*tasks)

        # Aggregate results
        for port, result in zip(range(START_PORT, END_PORT), results):
            if result:
                print(f"Processing stats from proxy {port}")
                aggregate_proxy_stats(result, stats_total)

    return stats_total


def save_stats(stats: Dict[str, Any], filepath: str) -> None:
    try:
        with open(filepath, "w") as stat_file:
            json.dump(stats, stat_file, indent=2)
            stat_file.write("\n")
        print(f"Statistics saved to {filepath}")
    except IOError as e:
        print(f"Error writing to file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


async def main() -> None:
    """Main entry point for the statistics collection script."""
    stats_total = await collect_all_stats()
    save_stats(stats_total, OUTPUT_FILE)


if __name__ == "__main__":
    asyncio.run(main())
