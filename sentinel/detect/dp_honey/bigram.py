"""Per-format character-bigram honeytoken generator with epsilon-DP over the count table.

We learn the internal character statistics of a format from a synthetic corpus, add Laplace
noise to the bigram counts (so no individual training string is recoverable — the DP property),
then sample a body and snap it onto the format mask (prefix/length/alphabet). The result is a
structurally valid, realistic-looking fake credential. Realism is what keeps eq.5's catch
probability from collapsing (the attacker can't cheaply tell fake from real).
"""

from __future__ import annotations

import numpy as np

from sentinel.detect.dp_honey.formats import CredFormat

BOS = "\x02"
EOS = "\x03"


class DPBigramModel:
    def __init__(self, fmt: CredFormat, epsilon: float = 1.0) -> None:
        self.fmt = fmt
        self.epsilon = epsilon
        self.symbols = [BOS, EOS, *list(fmt.alphabet)]
        self.idx = {s: i for i, s in enumerate(self.symbols)}
        self.P: np.ndarray | None = None

    def fit(self, corpus: list[str], seed: int = 0) -> "DPBigramModel":
        rng = np.random.default_rng(seed)
        s = len(self.symbols)
        counts = np.zeros((s, s), dtype=np.float64)
        max_bigrams = 0
        for ex in corpus:
            body = ex[len(self.fmt.prefix):]
            seq = [BOS, *list(body), EOS]
            max_bigrams = max(max_bigrams, len(seq) - 1)
            for a, b in zip(seq[:-1], seq[1:]):
                if a in self.idx and b in self.idx:
                    counts[self.idx[a], self.idx[b]] += 1.0

        # epsilon-DP: L1 sensitivity of the histogram to one example is its bigram count.
        sensitivity = max(1, max_bigrams)
        scale = sensitivity / self.epsilon
        noisy = counts + rng.laplace(0.0, scale, size=counts.shape)
        noisy = np.clip(noisy, 0.0, None)

        row = noisy.sum(axis=1, keepdims=True)
        # Dead rows -> uniform over real symbols (exclude BOS column).
        self.P = np.where(row > 0, noisy / np.where(row == 0, 1, row), 0.0)
        for i in range(s):
            if row[i] == 0:
                self.P[i, 2:] = 1.0 / (s - 2)
        # Never transition *into* BOS.
        self.P[:, self.idx[BOS]] = 0.0
        self.P /= self.P.sum(axis=1, keepdims=True)
        return self

    def sample(self, rng: np.random.Generator | None = None) -> str:
        if self.P is None:
            raise RuntimeError("call fit() first")
        rng = rng or np.random.default_rng()
        body_chars: list[str] = []
        prev = BOS
        for _ in range(self.fmt.body_len * 3):
            nxt = self.symbols[rng.choice(len(self.symbols), p=self.P[self.idx[prev]])]
            if nxt == EOS:
                break
            if nxt in self.fmt.alphabet:
                body_chars.append(nxt)
            prev = nxt
            if len(body_chars) >= self.fmt.body_len:
                break

        # Format mask repair: pad/truncate to exact length using the format alphabet.
        while len(body_chars) < self.fmt.body_len:
            body_chars.append(rng.choice(list(self.fmt.alphabet)))
        body = "".join(body_chars[: self.fmt.body_len])
        return self.fmt.prefix + body
