"""AI-Powered IoT Network Intrusion Detection System."""


def main() -> None:
    """Start the API server on localhost (``uv run major-project``)."""
    import uvicorn

    uvicorn.run("major_project.main:app", host="127.0.0.1", port=8000)
