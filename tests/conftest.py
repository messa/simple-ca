import logging
from pathlib import Path
from pytest import fixture


logging.basicConfig(level=logging.DEBUG)


def temp_dir(tmpdir):
    return Path(str(tmpdir))
