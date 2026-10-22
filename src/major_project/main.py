"""ASGI entry point: ``uv run uvicorn major_project.main:app --host 127.0.0.1 --port 8000``."""

from major_project.app import create_app

app = create_app()
