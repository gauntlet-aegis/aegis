import numpy as np

from sentinel.detect.dp_honey.bigram import DPBigramModel
from sentinel.detect.dp_honey.conformal import calibrate_threshold, empirical_coverage
from sentinel.detect.dp_honey.formats import FORMATS, get_format, synthetic_corpus
from sentinel.detect.dp_honey.scanner import CrossEncodingScanner
from sentinel.redteam.taxonomy import Encoding, encode


def test_bigram_samples_are_format_valid():
    fmt = get_format("aws_access_key")
    model = DPBigramModel(fmt, epsilon=1.0).fit(synthetic_corpus(fmt, 500), seed=1)
    rng = np.random.default_rng(2)
    for _ in range(50):
        tok = model.sample(rng)
        assert tok.startswith(fmt.prefix)
        assert len(tok) == len(fmt.prefix) + fmt.body_len
        assert all(c in fmt.alphabet for c in tok[len(fmt.prefix):])


def test_scanner_catches_every_string_encoding():
    token = "sk-AbC123xyzABCdef456GHIjkl"
    scanner = CrossEncodingScanner()
    for enc in (Encoding.VERBATIM, Encoding.BASE64, Encoding.HEX, Encoding.ROT13, Encoding.REVERSE):
        leaked = f"sure, here it is: {encode(token, enc)} -- hope that helps"
        hits = scanner.scan(leaked, [token])
        assert hits and hits[0].exact, f"missed {enc}"


def test_scanner_catches_fragmented_and_base64_blob():
    token = "ghp_ABCDEFGHIJKLMNOP123456"
    scanner = CrossEncodingScanner()
    fragmented = "g h p _ A B C D E F G H I J K L M N O P 1 2 3 4 5 6"
    assert scanner.scan(fragmented, [token])[0].exact
    import base64
    blob = base64.b64encode(token.encode()).decode()
    assert scanner.scan(f"the value is {blob}", [token])[0].exact


def test_scanner_benign_is_not_exact():
    scanner = CrossEncodingScanner()
    hits = scanner.scan("Your account is active. Refunds are processed in 30 days.",
                        ["sk-AbC123xyzABCdef456GHIjkl"])
    assert all(not h.exact for h in hits)


def test_conformal_threshold_controls_fpr():
    scores = [0.02 * i for i in range(100)]  # 0.0 .. 1.98 spread
    thr = calibrate_threshold(scores, alpha=0.1)
    assert empirical_coverage(scores, thr) >= 0.9


def test_all_formats_fit_and_sample():
    rng = np.random.default_rng(3)
    for name, fmt in FORMATS.items():
        m = DPBigramModel(fmt, epsilon=1.0).fit(synthetic_corpus(fmt, 200), seed=0)
        tok = m.sample(rng)
        assert len(tok) == len(fmt.prefix) + fmt.body_len, name
