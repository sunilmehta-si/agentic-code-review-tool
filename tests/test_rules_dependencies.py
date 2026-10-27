import unittest

from agentic_code_review.rules.dependencies import pinned_versions

from .helpers import ids

LOCK = {"lockfile"}

UV_LOCK = '''version = 1
revision = 2
requires-python = ">=3.10"

[[package]]
name = "certifi"
version = "{certifi}"
source = {{ registry = "https://pypi.org/simple" }}

[[package]]
name = "charset-normalizer"
version = "3.4.2"
source = {{ registry = "https://pypi.org/simple" }}
'''


class PinnedVersionsTests(unittest.TestCase):
    def test_reads_each_lock_format_and_points_at_the_version_line(self):
        uv = UV_LOCK.format(certifi="2026.1.4").splitlines()
        self.assertEqual(list(pinned_versions("uv.lock", uv)), [("certifi", "2026.1.4", 7), ("charset-normalizer", "3.4.2", 12)])
        pipfile = ['{', '  "default": {', '    "certifi": {', '      "hashes": [],', '      "version": "==2025.8.3"', '    }']
        self.assertEqual(list(pinned_versions("Pipfile.lock", pipfile)), [("certifi", "2025.8.3", 5)])
        pip = ["# pinned", "Certifi==2026.4.22 \\", "    --hash=sha256:abc", "requests[socks]==2.32.4 ; python_version >= '3.9'", "flask>=3"]
        self.assertEqual(list(pinned_versions("requirements.txt", pip)), [("certifi", "2026.4.22", 2), ("requests", "2.32.4", 4)])


class CertifiRootsRule(unittest.TestCase):
    def test_certifi_before_the_emsign_removal_is_flagged_in_every_format(self):
        self.assertIn("ACR-DEP-001", ids("python/kserve/uv.lock", UV_LOCK.format(certifi="2026.1.4"), LOCK))
        self.assertIn("ACR-DEP-001", ids("poetry.lock", '[[package]]\nname = "certifi"\nversion = "2026.10.5"\n', LOCK))
        self.assertIn("ACR-DEP-001", ids("requirements.txt", "certifi==2025.8.3\n", LOCK))
        self.assertIn("ACR-DEP-001", ids("Pipfile.lock", '"certifi": {\n  "version": "==2026.4.22"\n}\n', LOCK))

    def test_fixed_and_later_releases_and_unpinned_certifi_are_fine(self):
        for version in ("2026.10.23", "2026.11.1", "2027.1.5"):
            self.assertNotIn("ACR-DEP-001", ids("uv.lock", UV_LOCK.format(certifi=version), LOCK), version)
        self.assertNotIn("ACR-DEP-001", ids("requirements.txt", "certifi>=2024.1.1\n", LOCK))
        self.assertNotIn("ACR-DEP-001", ids("requirements.txt", "certifi==2025.8.3  # acr:ignore[ACR-DEP-001]\n", LOCK))
        # another package's version on the line after a name must not be read as certifi's
        self.assertNotIn("ACR-DEP-001", ids("uv.lock", '[[package]]\nname = "certifi-extras"\nversion = "2020.1.1"\n', LOCK))
