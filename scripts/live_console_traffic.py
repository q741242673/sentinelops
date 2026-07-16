from __future__ import annotations

import argparse
import asyncio
from collections import Counter

import httpx


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Keep the live console alert and telemetry active")
    parser.add_argument("--order-url", required=True)
    parser.add_argument("--interval", type=float, default=0.25)
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    outcomes: Counter[str] = Counter()
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        while True:
            try:
                response = await client.post(f"{args.order_url.rstrip('/')}/checkout")
                outcomes[str(response.status_code)] += 1
            except httpx.HTTPError:
                outcomes["network_error"] += 1
            total = sum(outcomes.values())
            if total and total % 40 == 0:
                print(f"live console traffic: {dict(outcomes)}", flush=True)
            await asyncio.sleep(args.interval)


if __name__ == "__main__":
    asyncio.run(main())
