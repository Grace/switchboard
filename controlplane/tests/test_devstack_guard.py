"""`devstack.py keys` must not run outside local development.

The subcommand prints an Ed25519 signing seed and four bearer tokens to stdout,
which is exactly right for its purpose: `dev-up.sh` redirects it into `.dev/env`.

It needs a guard because the file ships in the production image.
`Dockerfile.controlplane` copies it because `quickstart.yaml`'s bootstrap task
runs `scripts/devstack.py dbinit` -- migrations and the runtime login -- so
excluding the file is not available. That leaves `keys` present in a production
image whose stdout is a CloudWatch log group, one run-task override away.

Nothing invokes it there today. This test exists so nothing can start to.
"""
import importlib.util
import os
import pathlib
import unittest

_DEVSTACK = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "devstack.py"


def _load():
    """Import devstack.py by path; scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location("devstack_under_test", _DEVSTACK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Args:
    key_id = "key-test"
    tenant = "tenant-test"


class DevstackKeysGuard(unittest.TestCase):
    def setUp(self):
        self.devstack = _load()
        self._saved = os.environ.get(self.devstack.DEV_MARKER)
        os.environ.pop(self.devstack.DEV_MARKER, None)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop(self.devstack.DEV_MARKER, None)
        else:
            os.environ[self.devstack.DEV_MARKER] = self._saved

    def test_refuses_without_the_marker(self):
        with self.assertRaises(SystemExit) as caught:
            self.devstack.cmd_keys(_Args())
        message = str(caught.exception)
        # The refusal has to say why and what to do, or the next person deletes
        # the guard rather than setting the variable.
        self.assertIn(self.devstack.DEV_MARKER, message)
        self.assertIn("stdout", message)

    def test_refuses_when_the_marker_is_empty(self):
        # An unset variable and one set to "" are the same intent, and compose
        # interpolating a missing value produces the second.
        os.environ[self.devstack.DEV_MARKER] = ""
        with self.assertRaises(SystemExit):
            self.devstack.cmd_keys(_Args())

    def test_generates_when_the_marker_is_set(self):
        os.environ[self.devstack.DEV_MARKER] = "1"
        import io
        import contextlib

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.devstack.cmd_keys(_Args())
        emitted = {line.split("=", 1)[0] for line in buffer.getvalue().splitlines() if line}
        self.assertEqual(
            emitted,
            {"POLICY_KEY_ID", "POLICY_SIGNING_SEED", "POLICY_PUBLIC_KEY",
             "BOOTSTRAP_ADMIN_TOKEN", "CONTROL_TOKEN", "LOCAL_TOKEN",
             "APP_DB_PASSWORD", "TENANT"},
        )

    def test_dbinit_is_not_guarded(self):
        # dbinit is the production entrypoint and must stay reachable. It fails
        # here for want of a database, which is the point: the failure is about
        # configuration, not about the marker.
        with self.assertRaises(SystemExit) as caught:
            self.devstack.cmd_dbinit(_Args())
        self.assertNotIn(self.devstack.DEV_MARKER, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
