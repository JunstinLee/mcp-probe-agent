"""Smoke tests for module imports."""

import pytest


def test_logger_import():
    """Assert logger module can be imported."""
    from src import logger
    assert logger is not None


def test_validators_import():
    """Assert validators module can be imported."""
    from src import validators
    assert validators is not None