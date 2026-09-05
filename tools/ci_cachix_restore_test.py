"""Test the cache verifier without network access or Nix builds."""

import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from ci_cachix_restore import CACHIX, UPSTREAM, restore, upstream_has, validate_paths


PYTHON = "/nix/store/" + "a" * 32 + "-python-env"
XED = "/nix/store/" + "b" * 32 + "-ixyk-xed-enc2"
UPSTREAM_PATH = "/nix/store/" + "c" * 32 + "-bash"


class ClosureTest(unittest.TestCase):
    def test_manifest_validation(self):
        self.assertEqual(validate_paths(json.dumps([XED, PYTHON, XED])), [PYTHON, XED])
        for invalid in [
            "null",
            "{}",
            "[]",
            "[1]",
            '["--repair"]',
            '["/nix/store/not-a-hash"]',
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_paths(invalid)

    def test_upstream_hit(self):
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with patch("ci_cachix_restore.urlopen", return_value=response) as request:
            self.assertTrue(upstream_has(UPSTREAM_PATH))
            request.assert_called_once_with(
                f"{UPSTREAM}/{'c' * 32}.narinfo", timeout=30
            )

    def test_only_404_is_a_miss(self):
        for code in [404, 403, 429, 500]:
            with (
                self.subTest(code=code),
                patch(
                    "ci_cachix_restore.urlopen",
                    side_effect=HTTPError(UPSTREAM, code, "error", None, None),
                ),
            ):
                if code == 404:
                    self.assertFalse(upstream_has(XED))
                else:
                    with self.assertRaises(HTTPError):
                        upstream_has(XED)
        with (
            patch("ci_cachix_restore.urlopen", side_effect=URLError("offline")),
            self.assertRaises(URLError),
        ):
            upstream_has(XED)

    def test_restores_python_and_xed_not_upstream_only_roots(self):
        with (
            patch(
                "ci_cachix_restore.upstream_has",
                side_effect=lambda path: path == UPSTREAM_PATH,
            ),
            patch("ci_cachix_restore.Path.exists", return_value=False),
            patch("ci_cachix_restore.subprocess.run") as run,
        ):
            restore(json.dumps([PYTHON, XED, UPSTREAM_PATH]))
            run.assert_called_once_with(
                [
                    "nix-store",
                    "--realise",
                    PYTHON,
                    XED,
                    "--max-jobs",
                    "0",
                    "--option",
                    "builders",
                    "",
                    "--option",
                    "substituters",
                    f"{CACHIX} {UPSTREAM}",
                    "--option", "extra-trusted-public-keys",
                    "ixyk.cachix.org-1:BcMtFvSIYCFngmXH/S8028XN4katnbBRoD898nm3g3M=",
                ],
                check=True,
            )

    def test_missing_cachix_output_fails(self):
        with (
            patch("ci_cachix_restore.upstream_has", return_value=False),
            patch("ci_cachix_restore.Path.exists", return_value=False),
            patch(
                "ci_cachix_restore.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "nix-store"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            restore(json.dumps([XED]))

    def test_warm_or_upstream_only_closure_rejected(self):
        for cached, exists in [(True, False), (False, True)]:
            with (
                self.subTest(cached=cached),
                patch("ci_cachix_restore.upstream_has", return_value=cached),
                patch("ci_cachix_restore.Path.exists", return_value=exists),
                patch("ci_cachix_restore.subprocess.run") as run,
                self.assertRaises(ValueError),
            ):
                restore(json.dumps([XED]))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
