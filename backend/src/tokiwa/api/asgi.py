"""ASGI entry point: ``uvicorn tokiwa.api.asgi:app``."""

import os

from tokiwa.api.app import create_app

app = create_app(run_jobs=os.environ.get("TOKIWA_NO_JOBS") != "1")
