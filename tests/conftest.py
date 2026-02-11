import logging
from pathlib import Path


logging.basicConfig(level=logging.DEBUG, format='  %(name)s %(levelname)5s: %(message)s')


def temp_dir(tmpdir):
    return Path(str(tmpdir))
