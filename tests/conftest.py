"""Shared pytest fixtures — paths into package fixtures/ (no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def workflows_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "workflows"


@pytest.fixture
def trust_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "trust-policies"


@pytest.fixture
def hcl_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "hcl"
