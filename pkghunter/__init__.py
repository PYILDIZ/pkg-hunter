"""pkg-hunter: static triage of newly published PyPI packages.

Safety model: package files are downloaded into memory and read as text.
Nothing is ever extracted to disk, installed, imported, or executed.
"""

__version__ = "0.1.0"
