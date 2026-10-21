import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SERVER = Path(__file__).resolve().parents[1] / "test-studio" / "server.py"

class SmartAnalyticsValidation(unittest.TestCase):
    def test_fields_are_whitelisted_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = os.environ.get("HYROVI_TEST_DB")
            try:
                os.environ["HYROVI_TEST_DB"] = str(Path(tmp) / "events.sqlite3")
                spec = importlib.util.spec_from_file_location("hyrovi_test_smart", SERVER)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                good = dict(deviceType="tablet", screenPixels="2048x1536",
                            viewportPixels="1024x768", colorDepth="24",
                            orientation="portrait", connection="4g",
                            features="webgl,wasm,service-worker,touch-events",
                            pixelRatio="3+")
                accepted = module.sanitized_diagnostics({
                    **good, "password":"very-secret", "rawUA":"raw user agent",
                    "screenPixels_extra":"do not keep",
                    "timezone":"Europe/Berlin"
                })
                for key, value in good.items():
                    self.assertEqual(accepted[key], value, key)
                self.assertEqual(accepted["timezone"], "Europe/Berlin")
                self.assertNotIn("password", accepted)
                self.assertNotIn("rawUA", accepted)
                self.assertNotIn("screenPixels_extra", accepted)
                rejected = module.sanitized_diagnostics({
                    "features":"webgl,secret-stuff",
                    "deviceType":"unregistered",
                    "viewportPixels":"999999999x123456789",
                    "timezone":"B" * 200
                })
                self.assertEqual(rejected, {})
            finally:
                if before is None: os.environ.pop("HYROVI_TEST_DB", None)
                else: os.environ["HYROVI_TEST_DB"] = before

if __name__ == "__main__":
    unittest.main()
