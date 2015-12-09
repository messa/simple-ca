import logging
import subprocess

logger = logging.getLogger(__name__)


class OpenSSLCLI:

    '''
    Just a wrapper around the openssl command
    '''

    def __init__(self):
        self.logger = logger
        self.openssl_command = 'openssl'

    def __call__(self, *args):
        cmd = [self.openssl_command] + [str(a) for a in args]
        self.logger.debug('Running command: %s', ' '.join(cmd))
        p = subprocess.Popen(cmd,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
        out, err = p.communicate()
        if p.returncode != 0:
            raise OpenSSLCLIError('Command {} failed - return code {}'.format(cmd, p.returncode))
        return out


class OpenSSLCLIError (Exception):
    pass
