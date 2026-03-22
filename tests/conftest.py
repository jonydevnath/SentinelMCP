"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_name() -> str:
    """Sample name for testing."""
    return "TestUser"
