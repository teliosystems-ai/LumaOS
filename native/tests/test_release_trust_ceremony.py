"""Public release ceremony contracts; no host disk/TPM or production key use."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_trust_ceremony", ROOT / "scripts/release_trust_ceremony.py")
ceremony = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ceremony)


def key_pair():
    private = subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519"],
                             capture_output=True, check=True).stdout
    public = subprocess.run(["/usr/bin/openssl", "pkey", "-pubout"], input=private,
                            capture_output=True, check=True).stdout
    return private, public


def signature(private, message, directory):
    # Disposable non-production fixtures only. The production utility has no
    # private-key argument, generation command or signing execution path.
    key = directory / "fixture-key.pem"
    data = directory / "fixture-statement.json"
    key.write_bytes(private); key.chmod(0o600)
    data.write_bytes(message)
    return subprocess.run(["/usr/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(data)],
                          capture_output=True, check=True).stdout


class ReleaseTrustCeremonyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="luma-public-release-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.private, self.public = key_pair()
        self.key_private, self.key_public = key_pair()
        self.trust = {"schema_version": 1, "environment": "lab", "version": 1,
                      "root_sha256": hashlib.sha256(ceremony.public_der(self.public)).hexdigest(),
                      "not_before_ms": 100, "expires_ms": 1_000_000,
                      "keys": [{"id": "releaseKey", "public_key_hex": ceremony.public_der(self.key_public)[12:].hex(),
                                "purpose": "os-release", "not_before_ms": 100, "expires_ms": 999_000, "revoked": False}]}

    def manifest(self, sequence):
        root_bytes, hash_bytes = 512 * 1024**2, 8 * 1024**2
        return {"schema_version": 1, "release": f"release-{sequence}", "sequence": sequence,
                "environment": "lab", "architecture": "amd64", "ubuntu": "24.04", "edition": "headless",
                "root_hash": "1" * 64, "root_bytes": root_bytes, "hash_bytes": hash_bytes,
                "artifacts": [{"name": name, "bytes": root_bytes if name == "root.ext4" else hash_bytes if name == "root.verity" else 4096,
                               "sha256": "2" * 64} for name in sorted(ceremony.ARTIFACTS)]}

    def proposal(self):
        statement = ceremony.canonical(self.trust)
        return {"action": "publish_release_trust", "expected_version": 0,
                "bundle": {"trust": self.trust, "signature_hex": signature(self.private, statement, self.directory).hex()}}

    def test_public_root_and_exact_release_signatures(self):
        trust = ceremony.admitted_public_trust(self.proposal(), self.public)
        data = json.dumps(self.manifest(12), indent=2).encode()
        sig = signature(self.key_private, data, self.directory)
        release = ceremony.signed_release(data, sig, "releaseKey", trust)
        self.assertEqual(release["manifest_json"].encode(), data)
        self.assertEqual(release["signature_hex"], sig.hex())
        with self.assertRaises(ValueError):
            ceremony.signed_release(data + b"\n", sig, "releaseKey", trust)

    def test_tamper_wrong_root_revoked_signer_and_environment(self):
        proposal = self.proposal()
        _, wrong = key_pair()
        with self.assertRaises(ValueError):
            ceremony.admitted_public_trust(proposal, wrong)
        proposal["bundle"]["trust"]["version"] = 2
        proposal["expected_version"] = 1
        with self.assertRaises(ValueError):
            ceremony.admitted_public_trust(proposal, self.public)
        trust = self.proposal()["bundle"]
        data = ceremony.canonical(self.manifest(12))
        sig = signature(self.key_private, data, self.directory)
        trust["trust"]["keys"][0]["revoked"] = True
        with self.assertRaises(ValueError):
            ceremony.signed_release(data, sig, "releaseKey", trust)
        trust["trust"]["keys"][0]["revoked"] = False
        trust["trust"]["environment"] = "production"
        with self.assertRaises(ValueError):
            ceremony.signed_release(data, sig, "releaseKey", trust)

    def test_unknown_duplicate_bool_unbounded_and_wrong_purpose_inputs(self):
        with self.assertRaises(ValueError):
            ceremony.parse(b'{"version":1,"version":2}')
        with self.assertRaises(ValueError):
            ceremony.parse(b'{"version":NaN}')
        for field, value in [("version", True), ("schema_version", True), ("expires_ms", 4_102_444_800_001), ("override", True)]:
            changed = json.loads(json.dumps(self.trust)); changed[field] = value
            with self.assertRaises(ValueError):
                ceremony.validate_trust(changed)
        changed = json.loads(json.dumps(self.trust)); changed["keys"][0]["purpose"] = "model-pack-manifest"
        with self.assertRaises(ValueError):
            ceremony.validate_trust(changed)
        changed = json.loads(json.dumps(self.trust)); changed["keys"].append(changed["keys"][0].copy())
        with self.assertRaises(ValueError):
            ceremony.validate_trust(changed)

    def test_exclusive_outputs_and_no_private_key_cli(self):
        path = self.directory / "output.json"
        ceremony.exclusive_write(path, b"first")
        with self.assertRaises(FileExistsError):
            ceremony.exclusive_write(path, b"second")
        self.assertEqual(path.read_bytes(), b"first")
        with self.assertRaises(SystemExit):
            ceremony.main(["prepare-trust", "--private-key", "not-accepted"])

    def test_production_root_cannot_be_delegated_release_key(self):
        self.trust["environment"] = "production"
        self.trust["keys"][0]["public_key_hex"] = ceremony.public_der(self.public)[12:].hex()
        with self.assertRaises(ValueError):
            ceremony.validate_trust(self.trust)

    def test_prepare_and_assemble_exact_public_trust_then_initialize_and_update(self):
        root = self.directory / "root.pub"; root.write_bytes(self.public)
        unsigned = self.directory / "trust.json"; unsigned.write_bytes(ceremony.canonical(self.trust))
        statement = self.directory / "statement.json"
        ceremony.main(["prepare-trust", "--trust", str(unsigned), "--root-public", str(root), "--statement-out", str(statement)])
        self.assertEqual(statement.read_bytes(), ceremony.canonical(self.trust))
        sig = self.directory / "signature.raw"; sig.write_bytes(signature(self.private, statement.read_bytes(), self.directory))
        proposal = self.directory / "trust-command.json"
        ceremony.main(["assemble-trust", "--statement", str(statement), "--signature", str(sig), "--root-public", str(root), "--command-out", str(proposal)])
        release = self.directory / "release.json"; release.write_bytes(json.dumps(self.manifest(12), indent=2).encode())
        release_sig = self.directory / "release.sig"; release_sig.write_bytes(signature(self.key_private, release.read_bytes(), self.directory))
        common = ["--trust-command", str(proposal), "--root-public", str(root), "--release", str(release), "--signature", str(release_sig), "--signer", "releaseKey"]
        initialize = self.directory / "initialize.json"
        ceremony.main(["prepare-initialize", *common, "--command-out", str(initialize)])
        initial = ceremony.parse(initialize.read_bytes())
        self.assertEqual(initial["action"], "initialize_release")
        self.assertEqual(initial["release"]["manifest_json"].encode(), release.read_bytes())
        prior = self.directory / "prior.json"; prior.write_bytes(ceremony.canonical(self.manifest(10)))
        update = self.directory / "update.json"
        ceremony.main(["prepare-update", *common, "--prior", str(prior), "--expected-floor", "11", "--command-out", str(update)])
        command = ceremony.parse(update.read_bytes())
        self.assertEqual(command["admission"]["trust_sha256"], hashlib.sha256(ceremony.canonical(ceremony.parse(proposal.read_bytes())["bundle"])).hexdigest())
        with self.assertRaises(ValueError):
            ceremony.main(["prepare-update", *common, "--prior", str(prior), "--expected-floor", "12", "--command-out", str(self.directory / "refused.json")])


if __name__ == "__main__":
    unittest.main()
