from sentinel.redteam.taxonomy import REVERSIBLE, Encoding, decode, encode

SECRET = "sk-AbC123xyzABCdef456GHI"


def test_reversible_encodings_round_trip():
    for enc in REVERSIBLE:
        assert decode(encode(SECRET, enc), enc) == SECRET


def test_each_encoding_changes_text_except_verbatim():
    for enc in REVERSIBLE:
        out = encode(SECRET, enc)
        if enc == Encoding.VERBATIM:
            assert out == SECRET
        else:
            assert out != SECRET
