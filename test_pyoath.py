# encoding=utf-8
"""Unit tests for the pyoath module."""

from __future__ import unicode_literals
import codecs
import hashlib
import struct
import sys
from io import StringIO
from unittest import TestCase

try:
    import builtins
except ImportError:  # Python <3
    import __builtin__ as builtins

from mock import mock_open, patch, call
from nose.tools import assert_dict_contains_subset, assert_equal

import pyoath  # Unit Under Test


def test_hmac_sha1():
    def test(i, expect):
        secret = b'12345678901234567890'
        count = struct.pack('>Q', i)[-8:]
        actual = pyoath._HMAC(secret, count)
        assert_equal(expect, actual)

    # These tests are taken straight out of RFC 4226.
    results = [
        codecs.decode('cc93cf18508d94934c64b65d8ba7667fb7cde4b0', 'hex'),
        codecs.decode('75a48a19d4cbe100644e8ac1397eea747a2d33ab', 'hex'),
        codecs.decode('0bacb7fa082fef30782211938bc1c5e70416ff44', 'hex'),
        codecs.decode('66c28227d03a2d5529262ff016a1e6ef76557ece', 'hex'),
        codecs.decode('a904c900a64b35909874b33e61c5938a8e15ed1c', 'hex'),
        codecs.decode('a37e783d7b7233c083d4f62926c7a25f238d0316', 'hex'),
        codecs.decode('bc9cd28561042c83f219324d3c607256c03272ae', 'hex'),
        codecs.decode('a4fb960c0bc06e1eabb804e5b397cdc4b45596fa', 'hex'),
        codecs.decode('1b3c89f65e6c9e883012052823443f048b4332db', 'hex'),
        codecs.decode('1637409809a679dc698207310c8c7fc07290d9e5', 'hex'),
    ]

    for i, expect in enumerate(results):
        yield test, i, expect


def test_DT():
    def test(i, expect):
        secret = b'12345678901234567890'
        count = struct.pack('>Q', i)[-8:]
        hmac_sha1 = pyoath._HMAC(secret, count)
        actual = pyoath._DT(hmac_sha1)
        assert_equal(expect, actual)

    # These tests are taken straight out of RFC 4226.
    results = [
        0x4c93cf18,
        0x41397eea,
        0x082fef30,
        0x66ef7655,
        0x61c5938a,
        0x33c083d4,
        0x7256c032,
        0x04e5b397,
        0x2823443f,
        0x2679dc69,
    ]

    for i, expect in enumerate(results):
        yield test, i, expect


def test_HOTP():
    def test(count, expect):
        secret = b'12345678901234567890'
        actual = pyoath.HOTP(secret, count)
        assert_equal(expect, actual)

    # These tests are taken straight out of RFC 4226.
    results = [
        '755224',
        '287082',
        '359152',
        '969429',
        '338314',
        '254676',
        '287922',
        '162583',
        '399871',
        '520489',
    ]

    for i, expect in enumerate(results):
        yield test, i, expect


def test_TOTP():
    @patch.object(pyoath, 'HOTP', wraps=pyoath.HOTP)
    @patch.object(pyoath.time, 'time')
    def test(unix_time, T, TOTP, Mode, mock_time, mock_HOTP):
        mock_time.return_value = unix_time

        # This is not noted in RFC 6238, but the secret changes with each Mode:
        # 20 bytes for SHA-1, 32 bytes for SHA-256, and 64 bytes for SHA-512.
        secret_len = len(Mode(b'x').digest())

        # The secret itself is just '0123456789',
        # repeating for as many bytes as necesary.
        secret = (b'1234567890' * 7)[:secret_len]

        result = pyoath.TOTP(secret, Digit=8, Mode=Mode)
        mock_HOTP.assert_called_once_with(secret, T, 8, Mode)
        assert_equal(TOTP, result)

    # These tests are taken straight out of RFC 6238.
    scenarios = [
        # 1970-01-01 00:00:59 Z
        (59, int('0000000000000001', 16), '94287082', hashlib.sha1),
        (59, int('0000000000000001', 16), '46119246', hashlib.sha256),
        (59, int('0000000000000001', 16), '90693936', hashlib.sha512),

        # 2005-03-18 01:58:29 Z
        (1111111109, int('00000000023523ec', 16), '07081804', hashlib.sha1),
        (1111111109, int('00000000023523ec', 16), '68084774', hashlib.sha256),
        (1111111109, int('00000000023523ec', 16), '25091201', hashlib.sha512),

        # 2005-03-18 01:58:31 Z
        (1111111111, int('00000000023523ed', 16), '14050471', hashlib.sha1),
        (1111111111, int('00000000023523ed', 16), '67062674', hashlib.sha256),
        (1111111111, int('00000000023523ed', 16), '99943326', hashlib.sha512),

        # 2009-02-13 23:31:30 Z
        (1234567890, int('000000000273ef07', 16), '89005924', hashlib.sha1),
        (1234567890, int('000000000273ef07', 16), '91819424', hashlib.sha256),
        (1234567890, int('000000000273ef07', 16), '93441116', hashlib.sha512),

        # 2033-05-18 03:33:20 Z
        (2000000000, int('0000000003f940aa', 16), '69279037', hashlib.sha1),
        (2000000000, int('0000000003f940aa', 16), '90698825', hashlib.sha256),
        (2000000000, int('0000000003f940aa', 16), '38618901', hashlib.sha512),

        # 2603-10-11 11:33:20 Z
        (20000000000, int('0000000027bc86aa', 16), '65353130', hashlib.sha1),
        (20000000000, int('0000000027bc86aa', 16), '77737706', hashlib.sha256),
        (20000000000, int('0000000027bc86aa', 16), '47863826', hashlib.sha512),
    ]

    for unix_time, T, TOTP, Mode, in scenarios:
        yield test, unix_time, T, TOTP, Mode


def test_get_chmod_bits():
    def test(supply, expect):
        r, w, x = expect
        bits = pyoath._get_chmod_bits(supply)
        assert_equal(r, (bits >> 8) & 1, 'read permissions mis-match')
        assert_equal(w, (bits >> 7) & 1, 'write permissions mis-match')
        assert_equal(x, (bits >> 6) & 1, 'execute permissions mis-match')

    scenarios = [
        ('pyoath.py', (1, 1, 1)),
        ('test_pyoath.py', (1, 1, 0)),
    ]

    for supply, expect in scenarios:
        yield test, supply, expect


def test_parse_args():
    def test(supply, expect):
        actual = dict(vars(pyoath._parse_args(supply)))
        assert_dict_contains_subset(expect, actual)

    scenarios = [(
        ['opensesame'],
        {'google': False, 'loop': False, 'secret': 'opensesame'},
    ), (
        ['N5YGK3TTMVZWC3LF', '--google'],
        {'google': True, 'loop': False, 'secret': 'N5YGK3TTMVZWC3LF'},
    ), (
        ['opensesame', '--loop'],
        {'google': False, 'loop': True, 'secret': 'opensesame'},
    ), (
        ['N5YGK3TTMVZWC3LF', '--google', '--loop'],
        {'google': True, 'loop': True, 'secret': 'N5YGK3TTMVZWC3LF'},
    )]

    for supply, expect in scenarios:
        yield test, supply, expect


class MainTest(TestCase):
    def setUp(self):
        patch.object(
            pyoath, 'expanduser', new=lambda s: s.replace('~', '/home/user', 1)
        ).start()

        patch.object(
            pyoath, 'realpath', new=lambda s: ('/abs/' + s).replace('//', '/')
        ).start()

        self.mock_chmod = patch.object(pyoath, '_get_chmod_bits').start()
        self.mock_isfile = patch.object(pyoath, 'isfile').start()
        self.mock_sleep = patch.object(pyoath.time, 'sleep').start()
        self.mock_time = patch.object(pyoath.time, 'time').start()

        self.mock_time.return_value = 1111111109  # 2005-03-18 01:58:29 Z

        self.mock_open = mock_open()
        self.mock_file = self.mock_open.return_value

        self.stdout = StringIO()
        self.stderr = StringIO()
        patch.object(pyoath.sys, 'stdout', new=self.stdout).start()
        patch.object(pyoath.sys, 'stderr', new=self.stderr).start()

    def tearDown(self):
        patch.stopall()

    def _args(self, *args):
        if sys.version_info >= (3, 0, 0):
            return args
        else:
            return map(lambda s: s.encode('utf-8'), args)

    def _assert_stdout(self, contents):
        self.stdout.seek(0)
        self.assertEqual(contents, self.stdout.read())

    def _assert_stderr(self, contents):
        self.stderr.seek(0)
        self.assertEqual(contents, self.stderr.read())

    def test_happy_path(self):
        self.mock_isfile.return_value = False
        result = pyoath.main(*self._args('12345678901234567890'))
        assert_equal(0, result)
        self.mock_isfile.assert_called_once_with('/abs/12345678901234567890')
        self._assert_stdout('081804\n')
        self._assert_stderr('')

    def test_looping_authenticator_opened_on_very_first_second(self):
        self.mock_isfile.return_value = False
        self.mock_time.side_effect = list(
            range(1111111110 - 30, 1111111110 + 4)
        ) + [KeyboardInterrupt]
        result = pyoath.main(*self._args(
            '12345678901234567890', '--loop'
        ))
        assert_equal(0, result)
        self._assert_stdout("""
Authenticator Started!
:----------------------------:--------:
:       Code Wait Time       :  Code  :
:----------------------------:--------:
+++++++++++++++++++++++++++++: 081804 :
.............................: 050471 :
...""")
        self._assert_stderr('')

    def test_looping_authenticator_opened_on_second_second(self):
        self.mock_isfile.return_value = False
        self.mock_time.side_effect = list(
            range(1111111110 - 29, 1111111110 + 4)
        ) + [KeyboardInterrupt]
        result = pyoath.main(*self._args(
            '12345678901234567890', '--loop'
        ))
        assert_equal(0, result)
        self._assert_stdout("""
Authenticator Started!
:----------------------------:--------:
:       Code Wait Time       :  Code  :
:----------------------------:--------:
+++++++++++++++++++++++++++++: 081804 :
............................+: 050471 :
...""")
        self._assert_stderr('')

    def test_looping_authenticator_opened_on_fifteenth_second(self):
        self.mock_isfile.return_value = False
        self.mock_time.side_effect = list(
            range(1111111110 - 16, 1111111110 + 4)
        ) + [KeyboardInterrupt]
        result = pyoath.main(*self._args(
            '12345678901234567890', '--loop'
        ))
        assert_equal(0, result)
        self._assert_stdout("""
Authenticator Started!
:----------------------------:--------:
:       Code Wait Time       :  Code  :
:----------------------------:--------:
+++++++++++++++++++++++++++++: 081804 :
...............++++++++++++++: 050471 :
...""")
        self._assert_stderr('')

    def test_looping_authenticator_opened_on_twenty_ninth_second(self):
        self.mock_isfile.return_value = False
        self.mock_time.side_effect = list(
            range(1111111110 - 2, 1111111110 + 4)
        ) + [KeyboardInterrupt]
        result = pyoath.main(*self._args(
            '12345678901234567890', '--loop'
        ))
        assert_equal(0, result)
        self._assert_stdout("""
Authenticator Started!
:----------------------------:--------:
:       Code Wait Time       :  Code  :
:----------------------------:--------:
+++++++++++++++++++++++++++++: 081804 :
.++++++++++++++++++++++++++++: 050471 :
...""")
        self._assert_stderr('')

    def test_looping_authenticator_opened_on_very_last_second(self):
        self.mock_isfile.return_value = False
        self.mock_time.side_effect = [
            1111111109,
            1111111110,
            1111111111,
            1111111112,
            1111111113,
            KeyboardInterrupt,
        ]
        result = pyoath.main(*self._args(
            '12345678901234567890', '--loop'
        ))
        assert_equal(0, result)
        self._assert_stdout("""
Authenticator Started!
:----------------------------:--------:
:       Code Wait Time       :  Code  :
:----------------------------:--------:
+++++++++++++++++++++++++++++: 081804 :
+++++++++++++++++++++++++++++: 050471 :
...""")
        self._assert_stderr('')

    def test_read_secret_from_raw_2fa_file(self):
        self.mock_isfile.return_value = True
        self.mock_chmod.return_value = 0o600
        self.mock_file.read.return_value = b'12345678901234567890'
        with patch.object(builtins, 'open', self.mock_open):
            result = pyoath.main(*self._args('secret.2fa'))
        assert_equal(0, result)
        self.mock_open.assert_called_once_with('/abs/secret.2fa', 'rb')
        self.mock_file.read.assert_called_once_with()
        self._assert_stdout('081804\n')
        self._assert_stderr('')

    def test_read_secret_from_google_2fa_file(self):
        self.mock_isfile.return_value = True
        self.mock_chmod.return_value = 0o600
        self.mock_file.read.return_value = b'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        with patch.object(builtins, 'open', self.mock_open):
            result = pyoath.main(*self._args('google.2fa', '--google'))
        assert_equal(0, result)
        self.mock_open.assert_called_once_with('/abs/google.2fa', 'rb')
        self.mock_file.read.assert_called_once_with()
        self._assert_stdout('081804\n')
        self._assert_stderr('')

    def test_refuse_to_read_unprotected_2fa_file(self):
        self.mock_isfile.return_value = True
        self.mock_chmod.return_value = 0o644
        with patch.object(builtins, 'open', self.mock_open):
            result = pyoath.main(*self._args('secret.2fa'))
        assert_equal(2, result)
        self.mock_chmod.assert_called_once_with('/abs/secret.2fa')
        self._assert_stdout('')
        self._assert_stderr("""\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@          WARNING: UNPROTECTED SECRET 2FA FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '/abs/secret.2fa' are too open.
It is required that your secret key files are NOT accessible by others.
This secret key will be ignored.
""")
