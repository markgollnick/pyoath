"""PyPI Package descriptor file."""
import ast
from sys import version_info
if (version_info > (3, 0)):
    from configparser import ConfigParser
else:
    from ConfigParser import ConfigParser
from setuptools import setup


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

copy_of_setup_args = setup_args.copy()
for key, val in copy_of_setup_args.items():
    if key.endswith('_file'):
        data = get_version(val) if key.startswith('version') else read(val)
        setup_args[key[:-5]] = data
        del setup_args[key]
    elif key.endswith('_dict'):
        data = ast.literal_eval(val)
        setup_args[key[:-5]] = data
        del setup_args[key]
    elif key.endswith('_list'):
        data = val.split()
        setup_args[key[:-5]] = data
        del setup_args[key]


if __name__ == '__main__':
    setup(**setup_args)
