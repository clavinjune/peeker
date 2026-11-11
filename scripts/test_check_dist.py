import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("check_dist", Path(__file__).with_name("check-dist.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PublicationChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "assets").mkdir()
        (self.root / "index.html").write_text('<div id="root">KUBERNETES SECURITY</div><script src="/assets/app-abc.js"></script><link href="/assets/app-abc.css">')
        (self.root / "assets/app-abc.js").write_text("console.log('app')")
        (self.root / "assets/app-abc.css").write_text("body { margin: 0 }")

    def test_static_bundle(self):
        self.assertEqual(len(checker.check_dist(self.root)), 3)

    def test_rejects_sensitive_content(self):
        for payload in ["ghp_" + "a" * 36, "/Users/example/private", "//# sourceMappingURL=app.map", "client-key-data: example"]:
            with self.subTest(payload=payload[:10]):
                (self.root / "assets/app-abc.js").write_text(payload)
                with self.assertRaises(ValueError):
                    checker.check_dist(self.root)

    def test_rejects_extra_artifacts(self):
        (self.root / ".env").write_text("not-a-real-secret")
        with self.assertRaises(ValueError):
            checker.check_dist(self.root)

    def test_rejects_symlinks(self):
        asset = self.root / "assets/app-abc.js"
        asset.unlink()
        asset.symlink_to(self.root / "index.html")
        with self.assertRaises(ValueError):
            checker.check_dist(self.root)


if __name__ == "__main__":
    unittest.main()
