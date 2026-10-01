set windows-shell := ["powershell.exe", "-NoProfile", "-Command"]

test:
    uv run pytest -v

run *args:
    uv run headers {{args}}

lint:
    uv run ruff check .