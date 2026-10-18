"""Full live Nosana + Daytona run; fails honestly if the attack is resisted."""
import argparse
import asyncio

from agentzero.config import Settings
from agentzero.engine import RunManager
from agentzero.store import Store


async def check(scenario):
    settings = Settings.from_env()
    store = Store(settings.data_dir / "agentzero.sqlite3")
    manager = RunManager(settings, store)
    run_id = manager.start(scenario)
    print("Live run:", run_id, flush=True)
    try:
        await manager.task
    finally:
        await manager.shutdown()
    run = store.get(run_id)
    print("Status:", run["status"], "| Cleanup:", run["cleanup"], flush=True)
    if run.get("error"):
        print(run["error"], flush=True)
    expected = "baseline_passed" if scenario == "normal" else "succeeded"
    if run["status"] != expected:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", required=True)
    parser.add_argument("--scenario", choices=["normal", "readme-injection", "test-laundering"], default="readme-injection")
    args = parser.parse_args()
    asyncio.run(check(args.scenario))
