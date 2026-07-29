"""Tests for the minimal feature-flag module.

Verifies the contract documented in ``pwd_manager/feature_flags.py``:
  * defaults preserve current (pre-hardening) behaviour
  * env vars flip flags
  * unknown flag names raise
  * ``override_flag`` is a safe context manager
  * ``known_flags`` reflects env changes
"""

import os
import unittest
import warnings

from pwd_manager.feature_flags import (
    _FLAGS,
    default_for,
    is_enabled,
    known_flags,
    override_flag,
)


class TestFeatureFlags(unittest.TestCase):
    def setUp(self):
        # Snapshot env so we can restore it exactly, regardless of what
        # the local .env file has set.
        self._saved = {
            name: os.environ.get(name) for name in _FLAGS
        }
        # Clear all flags so each test starts from defaults.
        for name in _FLAGS:
            os.environ.pop(name, None)

    def tearDown(self):
        for name, val in self._saved.items():
            if val is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = val

    def test_all_defaults_are_false(self):
        """Every flag must default to False so importing the module never
        changes the app's current behaviour."""
        for name in _FLAGS:
            self.assertFalse(
                default_for(name), f"{name} defaults to True — unsafe"
            )
            self.assertFalse(is_enabled(name), f"{name} effective value is True")

    def test_env_var_enables_flag(self):
        os.environ["ENABLE_CSRF"] = "1"
        self.assertTrue(is_enabled("ENABLE_CSRF"))

    def test_env_var_disables_flag(self):
        os.environ["ENABLE_CSRF"] = "0"
        self.assertFalse(is_enabled("ENABLE_CSRF"))

    def test_truthy_strings_recognised(self):
        for val in ("1", "true", "TRUE", "Yes", "on"):
            os.environ["ENABLE_KEY_WRAPPING"] = val
            self.assertTrue(is_enabled("ENABLE_KEY_WRAPPING"), val)

    def test_falsy_strings_recognised(self):
        for val in ("0", "false", "no", "off", ""):
            os.environ["ENABLE_KEY_WRAPPING"] = val
            self.assertFalse(is_enabled("ENABLE_KEY_WRAPPING"), val)

    def test_unknown_value_warns_and_treats_as_false(self):
        os.environ["ENABLE_KEY_WRAPPING"] = "maybe"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertFalse(is_enabled("ENABLE_KEY_WRAPPING"))
        self.assertTrue(
            any(issubclass(w.category, RuntimeWarning) for w in caught),
            "Expected a RuntimeWarning for unrecognized flag value",
        )

    def test_unknown_flag_name_raises(self):
        with self.assertRaises(KeyError):
            is_enabled("DOES_NOT_EXIST")
        with self.assertRaises(KeyError):
            default_for("DOES_NOT_EXIST")
        with self.assertRaises(KeyError), override_flag("DOES_NOT_EXIST", True):
            pass

    def test_override_flag_restores_previous_value(self):
        os.environ["ENABLE_CSRF"] = "0"
        with override_flag("ENABLE_CSRF", True):
            self.assertTrue(is_enabled("ENABLE_CSRF"))
        # restored
        self.assertEqual(os.environ.get("ENABLE_CSRF"), "0")

    def test_override_flag_removes_unset_var(self):
        os.environ.pop("ENABLE_CSRF", None)
        with override_flag("ENABLE_CSRF", True):
            self.assertTrue(is_enabled("ENABLE_CSRF"))
        self.assertNotIn("ENABLE_CSRF", os.environ)

    def test_override_flag_restores_even_on_exception(self):
        os.environ["ENABLE_CSRF"] = "0"
        with self.assertRaises(RuntimeError), override_flag("ENABLE_CSRF", True):
            raise RuntimeError("boom")
        self.assertEqual(os.environ.get("ENABLE_CSRF"), "0")

    def test_known_flags_reflects_env(self):
        os.environ["ENABLE_CSRF"] = "1"
        snapshot = known_flags()
        self.assertTrue(snapshot["ENABLE_CSRF"])
        # other flags still default
        self.assertFalse(snapshot["ENABLE_KEY_WRAPPING"])

    def test_known_flags_covers_all_registered_flags(self):
        self.assertEqual(set(known_flags()), set(_FLAGS))


if __name__ == "__main__":
    unittest.main()
