"""Shared local storage helpers for the Talos dashboard/runtime."""

from __future__ import annotations

from pathlib import Path


def default_data_dir() -> Path:
    path = Path.home() / ".talos"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_db_path() -> Path:
    return default_data_dir() / "dashboard.db"
