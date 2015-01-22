"""PyPI Package descriptor file."""

from ConfigParser import ConfigParser
from distutils.core import setup


def get_version(change_log):
    """Return the latest version as noted in a change log."""
    lastline = [ln.strip() for ln in read(change_log).split('\n') if ln][-1]
    version = lastline.split(',')[0]
    return version[1:]


def read(file_name):
    """Read file contents."""
    f = None
    data = ''
    try:
        f = open(file_name, 'rb')
        data = f.read().decode('utf-8')
    except:
        pass
    finally:
        if f:
            f.close()
        return data


cfg = ConfigParser()
cfg.read('setup.cfg')
setup_args = dict(cfg.items('setup'))


for key, val in setup_args.items():
    if key.endswith('_file'):
        data = get_version(val) if key.startswith('version') else read(val)
        setup_args[key[:-5]] = data
        del setup_args[key]
    if key.endswith('_list'):
        setup_args[key[:-5]] = [val.strip() for val in val.split(',')]
        del setup_args[key]


if __name__ == '__main__':
    setup(**setup_args)
