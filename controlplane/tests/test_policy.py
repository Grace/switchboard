import base64
import copy
import json
from pathlib import Path
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from controlplane.policy import canonical, validate_policy

class PolicyTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[2]
        self.envelope = json.loads((root / "testdata/policy-envelope.json").read_text())
        self.payload = base64.b64decode(self.envelope["payload"])
        self.policy = json.loads(self.payload)
        self.public = base64.b64decode((root / "testdata/public-key.txt").read_text())

    def test_cross_language_signature(self):
        validate_policy(self.policy, "fixture", 1800000000)
        self.assertEqual(canonical(self.policy), self.payload)
        Ed25519PublicKey.from_public_bytes(self.public).verify(
            base64.b64decode(self.envelope["signature"]), b"switchboard-policy-v1\nfixture\n" + self.payload)

    def test_invalid_constraints(self):
        for field, value in (("version", True), ("version", 0), ("schema", 2), ("tenant", "other"),
                             ("expires_at", 1800000000), ("issued_at", 1800000100), ("routes", [])):
            with self.subTest(field=field, value=value):
                p = copy.deepcopy(self.policy)
                p[field] = value
                with self.assertRaises(ValueError):
                    validate_policy(p, "fixture", 1800000000)

    def test_unknown_fields(self):
        self.policy["extra"] = "bad"
        with self.assertRaises(ValueError):
            validate_policy(self.policy, "fixture", 1800000000)

if __name__ == "__main__":
    unittest.main()
