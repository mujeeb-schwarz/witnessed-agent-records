"""Malformed proof domains must fail before cryptographic verification."""
import unittest
from unittest.mock import patch
from nacl.signing import SigningKey
from witnessed_gate import checker
from witnessed_gate.common import ZERO_HASH, canon_bytes, chain_head, check_stamp, head_body, stamp_body


class ProofDomains(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.keys = {"w": self.key.verify_key.encode().hex()}
        self.fp = "a" * 64
        self.head = chain_head(ZERO_HASH, self.fp)

    def sign(self, body):
        return dict(body, sig=self.key.sign(canon_bytes(body)).signature.hex())

    def test_f13_one_entry_concatenation_ambiguity(self):
        head = self.sign(head_body("w", 1, self.head))
        proof = {"fp": "", "index": 0, "prev_head": ZERO_HASH + self.fp, "later": []}
        self.assertIsNotNone(checker.verify_inclusion("", proof, head, self.keys))

    def test_f13_stamp_domains_precede_crypto(self):
        base = stamp_body("w", self.fp, 0, self.head, 1)
        variants = [dict(base, index=-1, size=0), dict(base, index=False, size=True),
                    dict(base, t=-1), dict(base, t=True), dict(base, fp="x"),
                    dict(base, witness=[]), dict(base, head="A" * 64)]
        for field in base:
            variants.append({k: v for k, v in base.items() if k != field})
        for body in variants:
            with self.subTest(body=body):
                msg = self.sign(body)
                with patch("witnessed_gate.common.verify_signature") as verify:
                    self.assertIsNotNone(check_stamp(msg, body.get("fp"), self.keys))
                    verify.assert_not_called()

    def test_f13_inclusion_requires_complete_strict_domains(self):
        head = self.sign(head_body("w", 1, self.head))
        good = {"fp": self.fp, "index": 0, "prev_head": ZERO_HASH, "later": []}
        for proof in (dict(good, index=False), dict(good, index="0"), dict(good, index=-1),
                      dict(good, later=""), dict(good, later=["x"]),
                      {k: v for k, v in good.items() if k != "fp"}):
            with self.subTest(proof=proof):
                self.assertIsNotNone(checker.verify_inclusion(self.fp, proof, head, self.keys))

    def test_f13_heads_and_consistency_fingerprints_have_strict_domains(self):
        zero = self.sign(head_body("w", 0, ZERO_HASH))
        for body in (head_body("w", False, ZERO_HASH), head_body("w", -1, ZERO_HASH),
                     head_body("w", 0, "x"), {"kind": "head", "size": 0, "head": ZERO_HASH}):
            with self.subTest(body=body):
                self.assertIsNotNone(checker.verify_append_only(self.sign(body), zero, [], self.keys))
        short_head = self.sign(head_body("w", 1, chain_head(ZERO_HASH, "x")))
        self.assertIsNotNone(checker.verify_append_only(zero, short_head, ["x"], self.keys))

    def test_f13_both_head_schemas_are_checked_before_any_crypto(self):
        old = self.sign(head_body("w", 0, ZERO_HASH))
        malformed_new = self.sign(head_body("w", True, self.head))
        with patch("witnessed_gate.checker.verify_signature") as verify:
            self.assertIsNotNone(checker.verify_append_only(old, malformed_new, [self.fp], self.keys))
            verify.assert_not_called()
