"""Shared fixtures for Liun tests."""

import random
import pytest
from liun.gf61 import M61, rand_element


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: marks tests as slow (real Liu)")


@pytest.fixture
def rng():
    """Deterministic RNG for reproducible tests."""
    return random.Random(42)


@pytest.fixture
def sample_elements(rng):
    """10 random GF(M61) elements for property testing."""
    return [rand_element(rng) for _ in range(10)]


@pytest.fixture
def small_network_size():
    return 10


@pytest.fixture
def medium_network_size():
    return 50


@pytest.fixture
def sample_psk():
    """A deterministic 256-byte PSK for testing."""
    r = random.Random(99)
    return bytes(r.getrandbits(8) for _ in range(256))
