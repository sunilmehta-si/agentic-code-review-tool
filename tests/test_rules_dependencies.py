import unittest

from agentic_code_review.rules import base
from agentic_code_review.rules.dependencies import cooldown_days, pinned_versions

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
        self.assertIn("ACR-DEP-001", ids("requirements.txt", "certifi==2026.10.5\n", LOCK))     # just before the fix

    def test_fixed_and_later_releases_and_unpinned_certifi_are_fine(self):
        # 2026.10.18 and .19 are the advisory's fixed releases, not only the later .23
        for version in ("2026.10.18", "2026.10.19", "2026.10.23", "2026.11.1", "2027.1.5"):
            self.assertNotIn("ACR-DEP-001", ids("uv.lock", UV_LOCK.format(certifi=version), LOCK), version)
        self.assertNotIn("ACR-DEP-001", ids("requirements.txt", "certifi>=2024.1.1\n", LOCK))
        self.assertNotIn("ACR-DEP-001", ids("requirements.txt", "certifi==2025.8.3  # acr:ignore[ACR-DEP-001]\n", LOCK))
        # another package's version on the line after a name must not be read as certifi's
        self.assertNotIn("ACR-DEP-001", ids("uv.lock", '[[package]]\nname = "certifi-extras"\nversion = "2020.1.1"\n', LOCK))


class InsecurePackageSourceRule(unittest.TestCase):
    def test_plain_http_indexes_and_trusted_hosts_are_flagged(self):
        flagged = [
            ("uv.lock", '[[package]]\nname = "x"\nversion = "1.0"\nsource = { registry = "http://pypi.internal/simple" }\n'),
            ("poetry.lock", '[package.source]\ntype = "legacy"\nurl = "http://mirror.corp/simple"\n'),
            ("web/package-lock.json", '    "node_modules/x": {\n      "resolved": "http://registry.corp/x/-/x-1.0.0.tgz",\n'),
            ("requirements.txt", "--index-url http://pypi.corp/simple\nflask==3.0.0\n"),
            ("requirements.txt", "-i http://pypi.corp/simple\n"),
            ("requirements-dev.txt", "--extra-index-url=http://pypi.corp/simple\n"),
            ("requirements.txt", "--trusted-host pypi.corp\n"),
        ]
        for path, text in flagged:
            self.assertIn("ACR-DEP-002", ids(path, text, LOCK), text)

    def test_https_localhost_and_comments_are_fine(self):
        fine = [
            ("uv.lock", '[[package]]\nname = "x"\nsource = { registry = "https://pypi.org/simple" }\n'),
            ("requirements.txt", "--index-url https://pypi.corp/simple\n"),
            ("requirements.txt", "--index-url http://localhost:8080/simple\n"),
            ("requirements.txt", "-i http://127.0.0.1/simple\n"),
            ("requirements.txt", "# --index-url http://old.corp/simple\n"),
            ("requirements.txt", "--trusted-host pypi.corp  # acr:ignore[ACR-DEP-002]\n"),
            ("uv.lock", '[[package]]\nname = "x"\nsource = { registry = "http://localhost.evil.com/simple" }\n'),
        ]
        for path, text in fine[:-1]:
            self.assertNotIn("ACR-DEP-002", ids(path, text, LOCK), text)
        # a hostname that only starts with localhost is not this machine
        self.assertIn("ACR-DEP-002", ids(*fine[-1], LOCK))


class ExtraIndexRule(unittest.TestCase):
    def test_an_extra_index_in_a_pip_file_is_flagged(self):
        self.assertIn("ACR-DEP-003", ids("requirements.txt", "--extra-index-url https://pkgs.corp/simple\nacme-auth==1.2\n", LOCK))
        self.assertIn("ACR-DEP-003", ids("constraints.txt", "--extra-index-url=https://pkgs.corp/simple\n", LOCK))

    def test_a_single_index_and_other_lock_formats_are_fine(self):
        self.assertNotIn("ACR-DEP-003", ids("requirements.txt", "--index-url https://pkgs.corp/simple\nacme-auth==1.2\n", LOCK))
        self.assertNotIn("ACR-DEP-003", ids("requirements.txt", "--extra-index-url https://x/simple  # acr:ignore[ACR-DEP-003]\n", LOCK))
        # uv records the index each package came from in the lock, so the lock itself is not ambiguous
        self.assertNotIn("ACR-DEP-003", ids("uv.lock", '# --extra-index-url https://pkgs.corp/simple\n', LOCK))


class NpmGitDependencyRule(unittest.TestCase):
    GIT = ('{\n  "packages": {\n    "node_modules/left-pad": {\n      "version": "1.3.0",\n'
           '      "resolved": "git+ssh://git@github.com/org/left-pad.git#5ce5a42c3f6f1b2e8bb2c9a05c3f9f2a70ee1a2e",\n'
           '      "license": "MIT"\n    }\n  }\n}\n')
    REGISTRY = ('{\n  "packages": {\n    "node_modules/left-pad": {\n      "version": "1.3.0",\n'
                '      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",\n'
                '      "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEYvSwnx6YQ2MWJYwpFQqUNmO9lY+QKqRkmBqD8+ZB2P/bw=="\n'
                '    }\n  }\n}\n')

    def test_git_and_github_tarball_sources_without_a_hash_are_flagged(self):
        self.assertIn("ACR-DEP-004", ids("web/package-lock.json", self.GIT, LOCK))
        tarball = self.GIT.replace("git+ssh://git@github.com/org/left-pad.git#5ce5a42c3f6f1b2e8bb2c9a05c3f9f2a70ee1a2e",
                                   "https://codeload.github.com/org/left-pad/tar.gz/5ce5a42c3f6f1b2e8bb2c9a05c3f9f2a70ee1a2e")
        self.assertIn("ACR-DEP-004", ids("package-lock.json", tarball, LOCK))

    def test_registry_packages_with_integrity_and_other_files_are_fine(self):
        self.assertNotIn("ACR-DEP-004", ids("package-lock.json", self.REGISTRY, LOCK))
        self.assertNotIn("ACR-DEP-004", ids("requirements.txt", self.GIT, LOCK))


class MovingGitRequirementRule(unittest.TestCase):
    def test_branch_tag_or_no_ref_is_flagged_and_a_commit_is_not(self):
        for line in ("git+https://github.com/org/pkg.git@main#egg=pkg", "pkg @ git+https://github.com/org/pkg.git@v1.2.0",
                     "git+ssh://git@github.com/org/pkg.git", "pkg[extra] @ git+https://github.com/org/pkg@develop"):
            self.assertIn("ACR-DEP-005", ids("requirements.txt", line + "\n", LOCK), line)
        sha = "a" * 40
        for line in (f"pkg @ git+https://github.com/org/pkg.git@{sha}", f"git+https://github.com/org/pkg.git@{sha}#egg=pkg",
                     "requests==2.32.4", "# git+https://github.com/org/pkg.git@main"):
            self.assertNotIn("ACR-DEP-005", ids("requirements-dev.txt", line + "\n", LOCK), line)

    def test_only_pip_files_are_read(self):
        self.assertNotIn("ACR-DEP-005", ids("uv.lock", 'source = { git = "https://github.com/org/pkg?rev=main" }\n', LOCK))


DEPENDABOT = {"dependabot"}
UPDATES = "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n    schedule:\n      interval: weekly\n"


class CooldownDaysTests(unittest.TestCase):
    def test_no_cooldown_block_is_no_wait(self):
        self.assertEqual(cooldown_days({"package-ecosystem": "pip"}), 0)
        self.assertEqual(cooldown_days({"cooldown": None}), 0)
        self.assertEqual(cooldown_days({"cooldown": "14"}), 0)

    def test_default_days_is_the_wait_and_three_when_omitted(self):
        self.assertEqual(cooldown_days({"cooldown": {"default-days": 14}}), 14)
        self.assertEqual(cooldown_days({"cooldown": {"include": ["*"]}}), 3)

    def test_a_semver_level_sets_the_wait_for_that_bump_alone(self):
        self.assertEqual(cooldown_days({"cooldown": {"default-days": 14, "semver-patch-days": 1}}), 1)
        self.assertEqual(cooldown_days({"cooldown": {"default-days": 14, "semver-major-days": 30}}), 14)

    def test_the_default_does_not_matter_once_all_three_levels_are_set(self):
        levels = {"semver-major-days": 30, "semver-minor-days": 14, "semver-patch-days": 7}
        self.assertEqual(cooldown_days({"cooldown": {**levels}}), 7)
        self.assertEqual(cooldown_days({"cooldown": {**levels, "default-days": 1}}), 7)

    def test_a_value_that_is_not_a_whole_number_of_days_is_ignored(self):
        self.assertEqual(cooldown_days({"cooldown": {"default-days": "14"}}), 0)
        self.assertEqual(cooldown_days({"cooldown": {"default-days": True}}), 0)


class DependabotCooldownRule(unittest.TestCase):
    def findings(self, text, path=".github/dependabot.yml", kinds=DEPENDABOT):
        return [f for f in base.run_rules(path, text, kinds) if f.rule_id == "ACR-DEP-006"]

    def test_an_update_without_a_cooldown_is_flagged_at_its_own_line(self):
        text = UPDATES + "  - package-ecosystem: docker\n    directory: /\n"
        found = self.findings(text)
        self.assertEqual([f.line for f in found], [3, 7])
        self.assertIn("'pip' update has no cooldown", found[0].detail)
        self.assertIn("'docker' update has no cooldown", found[1].detail)

    def test_a_cooldown_of_a_week_or_more_is_accepted(self):
        for days in (7, 14, 30):
            with self.subTest(days=days):
                self.assertEqual(self.findings(UPDATES + f"    cooldown:\n      default-days: {days}\n"), [])

    def test_a_short_cooldown_is_flagged_with_its_length(self):
        found = self.findings(UPDATES + "    cooldown:\n      default-days: 3\n")
        self.assertEqual(len(found), 1)
        self.assertIn("waits 3 days", found[0].detail)
        self.assertIn("waits 1 day;", self.findings(UPDATES + "    cooldown:\n      default-days: 1\n")[0].detail)

    def test_a_short_level_is_flagged_even_with_a_long_default(self):
        text = UPDATES + "    cooldown:\n      default-days: 14\n      semver-patch-days: 0\n"
        self.assertEqual(len(self.findings(text)), 1)

    def test_only_the_updates_that_lack_one_are_flagged(self):
        text = UPDATES + "    cooldown:\n      default-days: 14\n  - package-ecosystem: docker\n    directory: /\n"
        self.assertEqual([f.line for f in self.findings(text)], [9])

    def test_the_inline_marker_on_the_entry_silences_it(self):
        text = UPDATES.replace("package-ecosystem: pip", "package-ecosystem: pip   # acr:ignore[ACR-DEP-006]")
        self.assertEqual(self.findings(text), [])

    def test_an_update_listed_with_another_key_first_still_reports(self):
        text = "version: 2\nupdates:\n  - directory: /\n    package-ecosystem: pip\n"
        found = self.findings(text)
        self.assertEqual([f.line for f in found], [2])         # no entry line to point at, so the updates: line

    def test_a_file_with_no_updates_or_broken_yaml_is_left_alone(self):
        self.assertEqual(self.findings("version: 2\n"), [])
        self.assertEqual(self.findings("updates: nope\n"), [])
        self.assertEqual(self.findings("updates: [\n"), [])
        self.assertEqual(self.findings("- just\n- a list\n"), [])

    def test_it_runs_on_the_dependabot_file_only(self):
        self.assertEqual(self.findings(UPDATES, path="ci.yml", kinds={"github-actions"}), [])
