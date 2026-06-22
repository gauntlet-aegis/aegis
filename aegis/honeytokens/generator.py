"""Honeytoken generator (PDF section 6.4) — DP-calibrated, format-matched canary synthesis.

For each supported credential format we build a small character-level bigram model trained ONLY
on synthetic, format-valid example strings (never real credentials). The bigram counts get
Laplace noise (epsilon ~1.0) added before sampling so the body characters are
differentially-private-flavored — the sampler can't memorize any single training example. After
sampling we ENFORCE a hard format mask (prefix / length / charset) by repair, so the output is
always format-valid even when the noisy model emits an out-of-charset character.

The DP step here is calibrated/demo-grade, not a formal (epsilon, delta) guarantee: it exists to
show the intended design (no memorization of training secrets), and because the training corpus
is synthetic there is no real secret to leak in the first place.

Where it fits: :class:`aegis.honeytokens.registry.HoneytokenRegistry` calls :func:`generate` to
mint the canary values it plants into model-visible context.
"""

from __future__ import annotations

import math
import random
import string
from dataclasses import dataclass

# Charsets used by the format masks below.
_UPPER_DIGITS = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits
_URLSAFE = string.ascii_letters + string.digits + "-_"
_B64URL = string.ascii_letters + string.digits + "-_"

# Laplace noise scale (b = sensitivity / epsilon, epsilon ~1.0) added to bigram counts so the
# model is DP-flavored — body characters never deterministically echo a single training sample.
_DP_EPSILON = 1.0
_DP_SCALE = 1.0 / _DP_EPSILON


@dataclass(frozen=True)
class Format:
    """A credential format: how to recognize/produce it.

    ``prefix`` is the literal lead-in; ``body_len`` is the number of generated body characters;
    ``charset`` is the alphabet body characters are drawn from. ``builder`` assembles the final
    string from a generated body (most formats just prepend the prefix; JWT is structured)."""

    name: str
    prefix: str
    body_len: int
    charset: str
    builder: "callable"


def _join_prefix(prefix: str, body: str) -> str:
    return prefix + body


def _build_jwt(prefix: str, body: str) -> str:
    """JWT-shaped canary: three base64url segments. Slice the generated body into 3 parts so the
    whole token is still driven by the (DP-flavored) sampler. The header segment is forced to start
    with ``eyJ`` (base64 of ``{"``) so the canary matches real JWT shape detectors / redaction."""
    n = len(body)
    a, b = body[: n // 3], body[n // 3 : 2 * n // 3]
    c = body[2 * n // 3 :]
    a = "eyJ" + (a[3:] if len(a) >= 3 else a)
    return f"{a}.{b}.{c}"


# Public registry of supported formats. Body lengths are chosen so the assembled token matches
# the real-world shape (e.g. AKIA + 16 chars; sk- + 32 chars).
FORMATS: dict[str, Format] = {
    "aws_access_key": Format("aws_access_key", "AKIA", 16, _UPPER_DIGITS, _join_prefix),
    "oauth_bearer": Format("oauth_bearer", "Bearer ", 32, _URLSAFE, _join_prefix),
    "openai_key": Format("openai_key", "sk-", 32, _ALNUM, _join_prefix),
    "jwt": Format("jwt", "", 60, _B64URL, _build_jwt),
    "stripe_live": Format("stripe_live", "sk_live_", 24, _ALNUM, _join_prefix),
    "github_pat": Format("github_pat", "ghp_", 36, _ALNUM, _join_prefix),
}


def _synthetic_corpus(fmt: Format, rng: random.Random, n: int = 24) -> list[str]:
    """Generate synthetic, format-valid example bodies to train the bigram model on.

    These are random draws over the format's own charset — never real credentials — so the model
    learns the *shape* (which characters are legal) without memorizing any real secret."""
    return ["".join(rng.choice(fmt.charset) for _ in range(fmt.body_len)) for _ in range(n)]


def _train_bigrams(corpus: list[str], charset: str, rng: random.Random) -> dict[str, dict[str, float]]:
    """Character-level bigram counts over ``corpus`` with Laplace noise added (DP-flavored).

    Returns ``{prev_char: {next_char: weight}}`` with a Laplace-noised, floored weight per
    transition so sampling can't deterministically reproduce a training example."""
    model: dict[str, dict[str, float]] = {c: {n: 0.0 for n in charset} for c in charset}
    for sample in corpus:
        for prev, nxt in zip(sample, sample[1:]):
            model[prev][nxt] += 1.0
    # Add Laplace(0, b) noise to every transition count, then floor at a small epsilon so every
    # legal next-character keeps a positive sampling weight (output stays in-charset).
    for prev in model:
        for nxt in model[prev]:
            noisy = model[prev][nxt] + _laplace(rng, _DP_SCALE)
            model[prev][nxt] = max(noisy, 1e-3)
    return model


def _laplace(rng: random.Random, scale: float) -> float:
    """Sample Laplace(0, scale) noise from a seeded RNG (deterministic given the seed)."""
    u = rng.random() - 0.5
    # Inverse-CDF of the Laplace distribution.
    return -scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))


def _sample_body(fmt: Format, model: dict[str, dict[str, float]], rng: random.Random) -> str:
    """Sample ``fmt.body_len`` characters from the bigram ``model``, then repair to the charset.

    The hard format mask: every emitted character is forced into ``fmt.charset`` (repair), so even
    if the noisy model somehow produced an illegal symbol the output is guaranteed format-valid."""
    chars = list(fmt.charset)
    prev = rng.choice(chars)
    out = [prev]
    for _ in range(fmt.body_len - 1):
        weights = [model[prev][c] for c in chars]
        nxt = rng.choices(chars, weights=weights, k=1)[0]
        out.append(nxt)
        prev = nxt
    # Hard mask / repair: drop anything outside the charset (defensive — sampling already in-set).
    repaired = [c if c in fmt.charset else rng.choice(chars) for c in out[: fmt.body_len]]
    return "".join(repaired)


def generate(fmt: str, seed: int | None = None) -> str:
    """Generate one format-valid honeytoken for ``fmt`` (a key of :data:`FORMATS`).

    Deterministic given ``seed`` (uses ``random.Random(seed)``). Raises ``KeyError`` for an
    unknown format. Output is always format-valid (prefix + masked body of the right length)."""
    spec = FORMATS[fmt]
    rng = random.Random(seed)
    corpus = _synthetic_corpus(spec, rng)
    model = _train_bigrams(corpus, spec.charset, rng)
    body = _sample_body(spec, model, rng)
    return spec.builder(spec.prefix, body)
