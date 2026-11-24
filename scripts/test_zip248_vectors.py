"""Tests for the vector generator; run with unittest discovery from scripts."""

import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import zip248_vectors as vectors

SCRIPT = Path(__file__).resolve().parent / "zip248_vectors.py"


class Zip248VectorsTests(unittest.TestCase):
    def test_fixed_expectations(self):
        generated = {
            f"{fixture}.{node}": digest.hex()
            for fixture, nodes in vectors.generate().items()
            for node, digest in nodes.items()
        }
        vectors.check_expected(
            generated,
            {
                **vectors.EXPECTED,
                **vectors.PREIMAGE_EXPECTED,
                **vectors.NULL_PREVOUT_EXPECTED,
                **{f"signature-mixed.{name}": digest
                   for name, digest in vectors.SIGNATURE_EXPECTED.items()},
            },
        )

    def test_compact_size_boundaries(self):
        # Exact encodings at both sides of every compactSize width transition.
        for value, encoded in (
            (0, "00"),
            (252, "fc"),
            (253, "fdfd00"),
            (65535, "fdffff"),
            (65536, "fe00000100"),
            (4294967295, "feffffffff"),
            (4294967296, "ff0000000001000000"),
            (18446744073709551615, "ffffffffffffffffff"),
        ):
            with self.subTest(value=value):
                self.assertEqual(vectors.compact_size(value).hex(), encoded)
        for value in (-1, 18446744073709551616):
            with self.assertRaises(ValueError):
                vectors.compact_size(value)

    def test_named_mismatch_is_not_an_assert(self):
        # This validation must also run with Python's -O optimization.
        with self.assertRaisesRegex(ValueError, "example: expected aa, generated bb"):
            vectors.check_expected({"example": "bb"}, {"example": "aa"})

    def test_rust_literal_inventory(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--check"],
            capture_output=True, text=True, check=True,
        )
        self.assertIn("Verified 42 named Rust hex constants", result.stdout)
        self.assertNotIn("NOT REPRODUCED", result.stdout)

    def test_signature_encoding_fixture_uses_a_different_txid(self):
        # The reproducible encoding fixture has a different S.2 input.
        generated = vectors.generate()["signature-encoding"]
        for name, expected in vectors.SIGNATURE_EXPECTED.items():
            with self.subTest(name=name):
                self.assertNotEqual(generated[name].hex(), expected)

    def test_seeded_signature_input_reproduces_existing_constants(self):
        generated = vectors.generate()["signature-mixed"]
        self.assertEqual(generated["txid-input"], vectors.mixed_signature_txid())
        for name, expected in vectors.SIGNATURE_EXPECTED.items():
            with self.subTest(name=name):
                self.assertEqual(generated[name].hex(), expected)

    def test_mixed_signature_txid_commits_to_explicit_shielded_fields(self):
        expected = vectors.mixed_signature_txid()
        path = SCRIPT.with_name("zip248_signature_effects.txt")
        original = path.read_text()
        # Change the first Sapling spend's cv, retaining counts and field lengths.
        prefix = "sapling="
        offset = len(prefix) + 2
        changed = original[:offset] + ("0" if original[offset] != "0" else "1") + original[offset + 1:]
        with mock.patch.object(Path, "read_text", return_value=changed):
            self.assertNotEqual(vectors.mixed_signature_txid(), expected)

    def test_null_prevout_fixture_matches_all_four_constants(self):
        generated = vectors.generate()["signature-null-prevout"]
        vectors.check_expected(
            {f"signature-null-prevout.{name}": digest.hex()
             for name, digest in generated.items()},
            vectors.NULL_PREVOUT_EXPECTED,
        )

    def test_wrong_signature_txid_fails(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--signature-txid", bytes(32).hex()],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature-mixed.transparent-0: expected", result.stderr)

    def test_invalid_signature_txid_is_rejected(self):
        for value in ("not-hex", "00"):
            with (
                self.subTest(value=value),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
                mock.patch.object(sys, "argv", [str(SCRIPT), "--signature-txid", value]),
            ):
                vectors.main()


if __name__ == "__main__":
    unittest.main()
