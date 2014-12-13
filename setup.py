"""PyPI package for pyoath."""

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


setup_args = dict(
    name='pyoath',
    version=get_version('CHANGES.txt'),
    description='Python OATH (One-time Authentication) implementation.',
    long_description=read('README.md'),
    author='Mark R. Gollnick &#10013;',
    author_email='mark.r.gollnick@gmail.com',
    url='https://github.com/markgollnick/pyoath',
    py_modules=['pyoath'],
    scripts=['pyoath']
)


if __name__ == '__main__':
    setup(**setup_args)
