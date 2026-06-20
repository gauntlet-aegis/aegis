"""Tests for the declarative grammar and format registry (U2)."""

from __future__ import annotations

import json

import numpy as np
import pytest

from detect.dp_honey import get_format, list_format_slugs, list_formats
from detect.dp_honey.errors import UnknownFormatError

# The format families the registry must cover (plan R4).
REQUIRED_SLUGS = {
    "aws-access-key-id",
    "aws-secret-access-key",
    "oauth-bearer",
    "generic-sk",
    "database-password",
    "jwt",
    "ssh-private-key",
    "stripe-sk-live",
    "github-ghp",
}


def test_registry_covers_all_required_formats():
    slugs = set(list_format_slugs())
    assert REQUIRED_SLUGS <= slugs
    for spec in list_formats():
        assert spec.slug, "every spec needs a slug"
        assert spec.name, "every spec needs a stable name"
        assert spec.safety_note, "every spec needs a safety note"
        # Shape-only invariant: nothing here is ever a real credential.
        assert spec.provider_valid is False


@pytest.mark.parametrize("slug", sorted(REQUIRED_SLUGS))
def test_synthetic_examples_validate_against_their_own_spec(slug):
    spec = get_format(slug)
    rng = np.random.default_rng(1234)
    for _ in range(25):
        example = spec.random_example(rng)
        assert spec.validate(example), (slug, example)


def test_unknown_format_raises():
    with pytest.raises(UnknownFormatError):
        get_format("does-not-exist")


def test_prefix_mismatch_fails_validation():
    spec = get_format("github-ghp")
    example = spec.random_example(np.random.default_rng(0))
    assert spec.validate(example)
    broken = "xxx_" + example[len("ghp_") :]
    assert not spec.validate(broken)


def test_length_mismatch_fails_validation():
    spec = get_format("github-ghp")
    example = spec.random_example(np.random.default_rng(0))
    assert not spec.validate(example + "EXTRA")
    assert not spec.validate(example[:-1])


def test_jwt_is_shape_only_not_a_real_token():
    spec = get_format("jwt")
    token = spec.random_example(np.random.default_rng(7))
    parts = token.split(".")
    assert len(parts) == 3 and all(parts), "JWT shape is three non-empty dot-joined parts"
    assert spec.provider_valid is False
    note = spec.safety_note.lower()
    assert "not" in note
    assert "signed" in note or "verifiable" in note


def test_ssh_is_shape_only_marker_not_a_usable_key():
    spec = get_format("ssh-private-key")
    token = spec.random_example(np.random.default_rng(9))
    assert "BEGIN OPENSSH PRIVATE KEY" in token
    assert "END OPENSSH PRIVATE KEY" in token
    assert spec.provider_valid is False
    note = spec.safety_note.lower()
    assert "marker" in note
    assert "not" in note


def test_database_password_predicate_enforced():
    spec = get_format("database-password")
    rng = np.random.default_rng(3)
    for _ in range(25):
        pw = spec.random_example(rng)
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)


def test_spec_hash_stable_and_snapshot_json_serializable():
    spec = get_format("aws-access-key-id")
    h1, h2 = spec.spec_hash(), spec.spec_hash()
    assert h1 == h2 and h1.startswith("sha256:")
    # The snapshot must be pure data (no callables leak in).
    snapshot = spec.to_snapshot()
    round_tripped = json.loads(json.dumps(snapshot))
    assert round_tripped["slug"] == "aws-access-key-id"
    assert round_tripped["provider_valid"] is False
