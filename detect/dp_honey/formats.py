"""The DP-HONEY format registry: shape-only specs for each secret family.

This module is the single source of truth for which secret families DP-HONEY can
imitate. Every value produced from these specs is synthetic and shape-only -- the
``provider_valid=False`` flag and the per-format ``safety_note`` make that
explicit at every downstream surface (CLI, artifacts, README matrix).
"""

from __future__ import annotations

from .errors import UnknownFormatError
from .grammar import (
    ALNUM,
    BASE64,
    BASE64URL,
    DIGITS,
    LOWER,
    PASSWORD,
    UPPER,
    UPPER_DIGITS,
    FormatSpec,
    Literal,
    Variable,
)

# Bump when the structure of any spec changes in a backward-incompatible way.
REGISTRY_VERSION = "1"

# Reusable disclaimer appended to every safety note.
SHAPE_ONLY = (
    "Shape-only synthetic value: not provider-valid, signed, decryptable, "
    "authenticated, or usable."
)


def _password_predicate(token: str) -> bool:
    """A realistic password constraint: at least one lower, upper, and digit.

    The per-character bigram sampler cannot guarantee class coverage, so this
    predicate is what makes bounded repair meaningful for this format.
    """
    return (
        any(c in LOWER for c in token)
        and any(c in UPPER for c in token)
        and any(c in DIGITS for c in token)
    )


_SPECS: tuple[FormatSpec, ...] = (
    FormatSpec(
        slug="aws-access-key-id",
        name="AWS Access Key ID",
        description="Amazon Web Services access key identifier (the public half of a key pair).",
        category="cloud-key",
        segments=(Literal("AKIA"), Variable("body", UPPER_DIGITS, 16)),
        safety_note="AKIA-prefixed identifier shape. " + SHAPE_ONLY,
    ),
    FormatSpec(
        slug="aws-secret-access-key",
        name="AWS Secret Access Key",
        description="Amazon Web Services secret access key (40-char base64-style secret).",
        category="cloud-secret",
        segments=(Variable("body", BASE64, 40),),
        safety_note="40-character AWS-secret shape. " + SHAPE_ONLY,
    ),
    FormatSpec(
        slug="oauth-bearer",
        name="OAuth Bearer Token",
        description="Generic OAuth 2.0 bearer access token (opaque base64url string).",
        category="token",
        segments=(Variable("token", BASE64URL, 40),),
        safety_note="Opaque bearer-token shape. " + SHAPE_ONLY,
    ),
    FormatSpec(
        slug="generic-sk",
        name="Generic sk- API Key",
        description="Generic 'sk-'-prefixed API key (OpenAI-style secret key shape).",
        category="api-key",
        segments=(Literal("sk-"), Variable("body", ALNUM, 48)),
        safety_note="'sk-'-prefixed API-key shape. " + SHAPE_ONLY,
    ),
    FormatSpec(
        slug="database-password",
        name="Database Password",
        description="Strong database password (mixed-class, no fixed prefix).",
        category="password",
        segments=(Variable("password", PASSWORD, 20),),
        safety_note="Random strong-password shape. " + SHAPE_ONLY,
        extra_predicate=_password_predicate,
    ),
    FormatSpec(
        slug="jwt",
        name="JWT-shaped Token",
        description="JSON Web Token shape: three base64url segments joined by dots.",
        category="jwt",
        segments=(
            Variable("header", BASE64URL, 20),
            Literal("."),
            Variable("payload", BASE64URL, 40),
            Literal("."),
            Variable("signature", BASE64URL, 43),
        ),
        safety_note=(
            "JWT-shaped only; the signature segment is random and the token is "
            "NOT signed or verifiable. " + SHAPE_ONLY
        ),
    ),
    FormatSpec(
        slug="ssh-private-key",
        name="SSH Private Key (shape marker)",
        description="OpenSSH private-key marker: PEM armor wrapping a short synthetic body.",
        category="private-key",
        segments=(
            Literal("-----BEGIN OPENSSH PRIVATE KEY----- "),
            Variable("body", BASE64URL, 64),
            Literal(" -----END OPENSSH PRIVATE KEY-----"),
        ),
        safety_note=(
            "Private-key-SHAPED marker only (PEM armor plus a short synthetic "
            "body). NOT a real, usable, or decryptable key. " + SHAPE_ONLY
        ),
    ),
    FormatSpec(
        slug="stripe-sk-live",
        name="Stripe sk_live_ Secret Key",
        description="Stripe live-mode secret key shape ('sk_live_' prefix).",
        category="api-key",
        segments=(Literal("sk_live_"), Variable("body", ALNUM, 24)),
        safety_note="'sk_live_'-prefixed Stripe-key shape. " + SHAPE_ONLY,
    ),
    FormatSpec(
        slug="github-ghp",
        name="GitHub Personal Access Token (ghp_)",
        description="GitHub personal access token shape ('ghp_' prefix).",
        category="vcs-token",
        segments=(Literal("ghp_"), Variable("body", ALNUM, 36)),
        safety_note="'ghp_'-prefixed GitHub-token shape. " + SHAPE_ONLY,
    ),
)

_FORMATS: dict[str, FormatSpec] = {spec.slug: spec for spec in _SPECS}


def list_format_slugs() -> list[str]:
    """Return all registered format slugs in stable (sorted) order."""
    return sorted(_FORMATS)


def list_formats() -> list[FormatSpec]:
    """Return all registered format specs in stable (sorted-by-slug) order."""
    return [_FORMATS[slug] for slug in list_format_slugs()]


def get_format(slug: str) -> FormatSpec:
    """Look up a format spec by slug, raising :class:`UnknownFormatError`."""
    try:
        return _FORMATS[slug]
    except KeyError:
        known = ", ".join(list_format_slugs())
        raise UnknownFormatError(
            f"unknown format: {slug!r}. Known formats: {known}"
        ) from None
