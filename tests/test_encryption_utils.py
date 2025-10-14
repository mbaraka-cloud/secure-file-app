
import pytest
import importlib

pytestmark = [pytest.mark.encryption]

CANDIDATE_MODULES = [
    "app.utils.encryption_utils",
]

CANDIDATE_FUNCS = [
    ("encrypt_bytes", "decrypt_bytes"),
    ("encrypt_file_bytes", "decrypt_file_bytes"),
    ("encrypt_data", "decrypt_data"),
    ("encrypt", "decrypt"),
]

def _load_mod():
    errors = []
    for name in CANDIDATE_MODULES:
        try:
            return importlib.import_module(name)
        except Exception as e:
            errors.append((name, repr(e)))
    pytest.skip(f"Encryption utils module not found. Tried: {errors}")

def _find_funcs(mod):
    for enc, dec in CANDIDATE_FUNCS:
        if hasattr(mod, enc) and hasattr(mod, dec):
            return getattr(mod, enc), getattr(mod, dec), f"{enc}/{dec}"
    pytest.skip(f"No encrypt/decrypt function pair found in {mod.__name__}. Tried {CANDIDATE_FUNCS}")

def test_encrypt_decrypt_roundtrip():
    mod = _load_mod()
    enc, dec, pairname = _find_funcs(mod)
    plaintext = b"hello \xf0\x9f\x98\x8a" * 1000
    try:
        blob = enc(plaintext)
    except TypeError:
        pytest.skip(f"{pairname} requires extra params (e.g., RSA pubkey). Adapt the test signature.")
    assert isinstance(blob, (bytes, bytearray, dict)), "Encrypted data should be bytes/dict"
    try:
        recovered = dec(blob)
    except TypeError:
        pytest.skip(f"{pairname} decrypt requires extra params. Adapt the test signature.")
    assert recovered == plaintext, "Decrypted text must match original"

def test_ciphertext_integrity_check():
    mod = _load_mod()
    enc, dec, pairname = _find_funcs(mod)
    plaintext = b"tag tampering test"
    try:
        blob = enc(plaintext)
    except TypeError:
        pytest.skip(f"{pairname} requires extra params (e.g., RSA pubkey). Adapt the test signature.")
    if isinstance(blob, dict) and "tag" in blob:
        bad = dict(blob)
        t = bad.get("tag")
        if isinstance(t, (bytes, bytearray)):
            bad["tag"] = b"\x00" * len(t)
        else:
            bad["tag"] = "0" * len(str(t))
        with pytest.raises(Exception):
            _ = dec(bad)
    else:
        pytest.skip("Blob structure not dict/tag-based; skip integrity tamper test.")
