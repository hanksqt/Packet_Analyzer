"""Shared pytest fixtures.

The one committed capture, ``tests/fixtures/sample.pcap``, is the golden fixture
the end-to-end test and CI run against. It is a real tcpdump capture, not a file
this project generated - see ``scripts/capture_sample.sh``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SAMPLE_PCAP = FIXTURE_DIR / "sample.pcap"


@pytest.fixture(scope="session")
def sample_pcap() -> Path:
    """Path to the committed golden capture."""
    if not SAMPLE_PCAP.exists():
        pytest.fail(
            f"{SAMPLE_PCAP} is missing. It is committed to the repo; if you are "
            f"regenerating it, run scripts/capture_sample.sh on Linux as root."
        )
    return SAMPLE_PCAP
