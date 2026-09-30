from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secret_vault import SecretVault, SecretVaultError


class SecretVaultTests(unittest.TestCase):
    def test_dpapi_roundtrip_and_plaintext_absent_from_vault_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vault.json"
            vault = SecretVault(path)
            secret = "sk-test-super-sensitive-value-123"
            vault.set_secret("openai_runtime", secret)
            self.assertEqual(vault.get_secret("openai_runtime"), secret)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn(secret, raw)
            self.assertNotIn("super-sensitive-value", raw)

    def test_target_binding_is_required_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = SecretVault(Path(directory) / "vault.json")
            vault.set_secret("openai_runtime", "sk-test-123")
            with self.assertRaises(SecretVaultError):
                vault.resolve_for_target(
                    "openai_runtime",
                    window_title="ChatGPT",
                    name="Runtime API key",
                )
            vault.bind_target(
                "openai_runtime",
                window_title="ChatGPT",
                name="Runtime API key",
            )
            self.assertEqual(
                vault.resolve_for_target(
                    "openai_runtime",
                    window_title="ChatGPT",
                    name="Runtime API key",
                ),
                "sk-test-123",
            )
            with self.assertRaises(SecretVaultError):
                vault.resolve_for_target(
                    "openai_runtime",
                    window_title="ChatGPT",
                    name="Chat with ChatGPT",
                )

    def test_metadata_exposes_alias_and_binding_but_never_secret_value(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = SecretVault(Path(directory) / "vault.json")
            secret = "secret-that-must-never-appear"
            vault.set_secret("runtime", secret)
            vault.bind_target("runtime", window_title="Settings", automation_id="api-key")
            metadata = vault.metadata()
            serialized = repr(metadata)
            self.assertIn("runtime", serialized)
            self.assertIn("api-key", serialized)
            self.assertNotIn(secret, serialized)
            self.assertFalse(metadata["secret_values_exposed"])
            self.assertFalse(metadata["remote_secret_upload_allowed"])
            self.assertTrue(metadata["target_binding_required"])

    def test_rejects_multiline_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = SecretVault(Path(directory) / "vault.json")
            with self.assertRaises(SecretVaultError):
                vault.set_secret("bad", "line1\nline2")


if __name__ == "__main__":
    unittest.main(verbosity=2)
