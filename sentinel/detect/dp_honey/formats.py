"""Credential-format registry.

Each format declares a prefix, a body alphabet, and a body length, plus a way to draw synthetic
format-valid examples (we never train on real secrets). The DP-bigram model learns the *internal*
character statistics of a format from this synthetic corpus; the format mask guarantees every
emitted honeytoken is structurally valid.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B64 = string.ascii_letters + string.digits + "+/"
ALNUM = string.ascii_letters + string.digits
PRINTABLE = string.ascii_letters + string.digits + "!@#$%^&*-_=+"


@dataclass(frozen=True)
class CredFormat:
    name: str
    prefix: str
    alphabet: str
    body_len: int

    def random_example(self) -> str:
        return self.prefix + "".join(secrets.choice(self.alphabet) for _ in range(self.body_len))


FORMATS: dict[str, CredFormat] = {
    "aws_access_key": CredFormat("aws_access_key", "AKIA", BASE32, 16),
    "aws_secret_key": CredFormat("aws_secret_key", "", B64, 40),
    "openai_key": CredFormat("openai_key", "sk-", ALNUM, 48),
    "github_pat": CredFormat("github_pat", "ghp_", ALNUM, 36),
    "stripe_key": CredFormat("stripe_key", "sk_live_", ALNUM, 24),
    "oauth_token": CredFormat("oauth_token", "ya29.", ALNUM + "-_", 40),
    "db_password": CredFormat("db_password", "", PRINTABLE, 20),
    "generic": CredFormat("generic", "", ALNUM, 20),
}


def get_format(name: str) -> CredFormat:
    return FORMATS.get(name, FORMATS["generic"])


def synthetic_corpus(fmt: CredFormat, n: int = 4000) -> list[str]:
    """A corpus of format-valid examples to train the bigram model (no real secrets involved)."""
    return [fmt.random_example() for _ in range(n)]
