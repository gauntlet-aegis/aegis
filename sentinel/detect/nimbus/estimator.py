"""Per-turn InfoNCE leakage estimate, in bits.

For one turn we score the (secret, this-turn-output) pair against a bank of benign-output
negatives and form the standard InfoNCE pointwise estimate:

    i_bits = clip( log2(K) + (f+ - logsumexp(scores))/ln2 ,  0,  log2(K) )

with K = N_neg + 1. The temperature sharpens the otherwise-flat cosine scores. The estimate is
ceiling-bounded at log2(K) per turn (PRD §6.4) — which is exactly why NIMBUS targets *accumulated*
leakage (the stage sums these), not single-turn blowouts (CIFT's job).
"""

from __future__ import annotations

import numpy as np

from sentinel.detect.nimbus.critic import LeakageCritic
from sentinel.detect.nimbus.encoder import CharNGramEncoder

LN2 = np.log(2.0)


def _logsumexp(x: np.ndarray) -> float:
    m = float(x.max())
    return m + float(np.log(np.exp(x - m).sum()))


class NimbusEstimator:
    def __init__(
        self,
        encoder: CharNGramEncoder,
        critic: LeakageCritic,
        neg_bank: np.ndarray,
        n_neg: int = 63,
        temperature: float = 0.1,
        seed: int = 0,
    ) -> None:
        self.encoder = encoder
        self.critic = critic
        self.neg_bank = neg_bank  # [M, dim] benign-output features
        self.n_neg = min(n_neg, len(neg_bank)) if len(neg_bank) else 0
        self.temperature = temperature
        self.rng = np.random.default_rng(seed)
        self._secret_cache: dict[str, np.ndarray] = {}

    def ceiling_bits(self) -> float:
        return float(np.log2(self.n_neg + 1)) if self.n_neg else 0.0

    def _secret_feat(self, secret: str) -> np.ndarray:
        f = self._secret_cache.get(secret)
        if f is None:
            f = self.encoder.encode(secret)
            self._secret_cache[secret] = f
        return f

    def infonce_bits(self, secret: str | None, conversation_id: str, output_text: str) -> float:
        if not secret or self.n_neg == 0:
            return 0.0
        s = self._secret_feat(secret)
        c = self.encoder.encode(output_text)
        pos = self.critic.score(s, c)

        if len(self.neg_bank) > self.n_neg:
            idx = self.rng.choice(len(self.neg_bank), size=self.n_neg, replace=False)
            negs = self.critic.score_batch(s, self.neg_bank[idx])
        else:
            negs = self.critic.score_batch(s, self.neg_bank)

        scores = np.concatenate([[pos], negs]) / self.temperature
        k = len(scores)
        lp = scores[0] - _logsumexp(scores)  # log-softmax of the positive (nats)
        bits = (np.log(k) + lp) / LN2
        return float(np.clip(bits, 0.0, np.log2(k)))
