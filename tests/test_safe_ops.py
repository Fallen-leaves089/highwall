from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from highwall.cli import main
from highwall.safe_ops import OpsRequest, SafeOpsError, SafeOpsPolicy, load_ops_plan


class SafeOpsPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.policy = SafeOpsPolicy((self.root,))

    def request(self, action: str, *targets: str, **values: object) -> OpsRequest:
        payload: dict[str, object] = {"action": action, "targets": list(targets)}
        payload.update(values)
        return OpsRequest.from_mapping(payload)

    def test_r0_read_status_is_allowed_without_targets(self) -> None:
        decision = self.policy.evaluate(self.request("read_status"))

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.risk, "R0")
        self.assertEqual(decision.requires_approval, ())

    def test_r1_requires_an_explicit_dry_run(self) -> None:
        target = self.root / "candidate.json"
        denied = self.policy.evaluate(self.request("dry_run_config", str(target)))
        allowed = self.policy.evaluate(
            self.request("dry_run_config", str(target), dry_run=True)
        )

        self.assertFalse(denied.allowed)
        self.assertIn("dry_run", " ".join(denied.reasons))
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.risk, "R1")

    def test_r2_mutations_are_denied_by_default(self) -> None:
        decision = self.policy.evaluate(
            self.request(
                "replace_config",
                str(self.root / "config.json"),
                dry_run=True,
                approval_reference="human-approved",
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.risk, "R2")
        self.assertIn("disabled", " ".join(decision.reasons))
        self.assertIn("verified backup", decision.requires_approval)
        self.assertIn("rollback plan", decision.requires_approval)

    def test_r3_operations_are_denied_even_with_claimed_approval(self) -> None:
        decision = self.policy.evaluate(
            self.request(
                "delete_data",
                str(self.root / "archive"),
                approval_reference="two-person-approved",
            )
        )

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.risk, "R3")
        self.assertIn("break-glass", " ".join(decision.reasons))
        self.assertIn("dual approval", decision.requires_approval)

    def test_raw_shell_is_never_accepted(self) -> None:
        decision = self.policy.evaluate(self.request("run_shell", "echo ok"))

        self.assertFalse(decision.allowed)
        self.assertIn("raw shell", " ".join(decision.reasons))

    def test_unknown_actions_are_rejected(self) -> None:
        decision = self.policy.evaluate(self.request("delete_everything"))

        self.assertFalse(decision.allowed)
        self.assertIn("unknown action", " ".join(decision.reasons))

    def test_relative_wildcard_variable_and_traversal_targets_are_rejected(self) -> None:
        unsafe = (
            "relative/config.json",
            str(self.root / "*.json"),
            str(self.root / "$HOME" / "config.json"),
            str(self.root / ".." / "outside.json"),
            "%TEMP%\\config.json",
            "\\\\.\\PhysicalDrive0",
            "\\\\server\\share\\config.json",
            str(self.root / "%2e%2e" / "config.json"),
            str(self.root / "config.json:secret"),
        )

        for target in unsafe:
            with self.subTest(target=target):
                decision = self.policy.evaluate(
                    self.request("dry_run_config", target, dry_run=True)
                )
                self.assertFalse(decision.allowed)

    def test_targets_outside_an_allowed_root_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as other_directory:
            outside = Path(other_directory).resolve() / "config.json"
            decision = self.policy.evaluate(
                self.request("dry_run_config", str(outside), dry_run=True)
            )

        self.assertFalse(decision.allowed)
        self.assertIn("allowed root", " ".join(decision.reasons))

    def test_no_allowed_roots_rejects_every_path_based_action(self) -> None:
        policy = SafeOpsPolicy(())
        decision = policy.evaluate(
            self.request(
                "dry_run_config",
                str(self.root / "config.json"),
                dry_run=True,
            )
        )

        self.assertFalse(decision.allowed)
        self.assertIn("allowed root", " ".join(decision.reasons))

    def test_symlink_component_is_rejected_when_platform_supports_it(self) -> None:
        outside = Path(self.temp.name + "-outside")
        outside.mkdir()
        self.addCleanup(lambda: outside.rmdir() if outside.exists() else None)
        link = self.root / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are not available")
        decision = self.policy.evaluate(
            self.request("dry_run_config", str(link / "config.json"), dry_run=True)
        )

        self.assertFalse(decision.allowed)
        self.assertIn("symbolic link", " ".join(decision.reasons))

    def test_plan_hash_is_stable_and_changes_with_targets(self) -> None:
        first = self.policy.evaluate(
            self.request("dry_run_config", str(self.root / "a.json"), dry_run=True)
        )
        second = self.policy.evaluate(
            self.request("dry_run_config", str(self.root / "a.json"), dry_run=True)
        )
        changed = self.policy.evaluate(
            self.request("dry_run_config", str(self.root / "b.json"), dry_run=True)
        )

        self.assertEqual(first.plan_sha256, second.plan_sha256)
        self.assertNotEqual(first.plan_sha256, changed.plan_sha256)

    def test_request_rejects_unknown_fields_and_bad_types(self) -> None:
        with self.assertRaisesRegex(SafeOpsError, "unknown field"):
            OpsRequest.from_mapping({"action": "read_status", "shell": "id"})
        with self.assertRaisesRegex(SafeOpsError, "targets"):
            OpsRequest.from_mapping({"action": "read_status", "targets": "one"})
        with self.assertRaisesRegex(SafeOpsError, "action"):
            OpsRequest.from_mapping({})


class SafeOpsCliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(args))
        return code, stdout.getvalue(), stderr.getvalue()

    def write_plan(self, directory: Path, payload: dict[str, object]) -> Path:
        path = directory / "plan.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_preview_emits_json_and_rejects_dangerous_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            plan = self.write_plan(
                root,
                {"action": "delete_data", "targets": [str(root / "data")]},
            )
            code, stdout, stderr = self.run_cli(
                "ops",
                "preview",
                "--plan",
                str(plan),
                "--allow-root",
                str(root),
                "--json",
            )

        self.assertEqual(code, 4, stderr)
        report = json.loads(stdout)
        self.assertFalse(report["allowed"])
        self.assertEqual(report["risk"], "R3")

    def test_preview_allows_read_only_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            plan = self.write_plan(
                root,
                {
                    "action": "dry_run_config",
                    "targets": [str(root / "candidate.json")],
                    "dry_run": True,
                },
            )
            code, stdout, stderr = self.run_cli(
                "ops",
                "preview",
                "--plan",
                str(plan),
                "--allow-root",
                str(root),
                "--json",
            )

        self.assertEqual(code, 0, stderr)
        self.assertTrue(json.loads(stdout)["allowed"])

    def test_plan_loader_rejects_duplicate_keys_and_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"action":"read_status","action":"delete_data"}', encoding="utf-8")
            oversized = root / "oversized.json"
            oversized.write_text("{" + " " * 70000 + "}", encoding="utf-8")

            with self.assertRaisesRegex(SafeOpsError, "duplicate"):
                load_ops_plan(duplicate)
            with self.assertRaisesRegex(SafeOpsError, "too large"):
                load_ops_plan(oversized)

    def test_preview_reports_invalid_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text("{", encoding="utf-8")
            code, _, stderr = self.run_cli("ops", "preview", "--plan", str(path))

        self.assertEqual(code, 2)
        self.assertIn("safe ops plan error", stderr)


if __name__ == "__main__":
    unittest.main()
