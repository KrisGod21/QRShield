import pytest

from app import demo_fixtures
from app.config import Settings
from app.db import DB


@pytest.fixture
def db():
    d = DB(":memory:")
    demo_fixtures.seed(d)
    return d


@pytest.fixture
def offline():
    """Demo fixtures on, network off: fully deterministic."""
    return Settings(demo_mode=True, online_checks=False, feeds=False)
