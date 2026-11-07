"""Compatibility ASGI entry point for deployments using backend.app.main:app."""
from backend.app.app.main import app

__all__ = ["app"]
