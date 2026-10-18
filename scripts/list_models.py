"""List current Nosana model IDs using only NOSANA_API_KEY from env/.env."""
import asyncio

from agentzero.config import Settings
from agentzero.inference import InferenceError, Nosana


async def main():
    try:
        models = await Nosana(Settings.from_env()).list_models()
    except InferenceError as exc:
        raise SystemExit(str(exc)) from None
    if not models:
        raise SystemExit("Nosana currently lists no served models. Try again later.")
    print("Available model IDs (copy an exact ID into WORKER_MODEL / SECURITY_MODEL):")
    for model in models:
        print(model["id"], "| context:", model.get("context_length", "not specified"))


if __name__ == "__main__":
    asyncio.run(main())
