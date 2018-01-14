"""Unit tests for the pyoath module."""

import codecs
import hashlib
import struct

from mock import patch
from nose.tools import assert_equal

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
        codecs.decode('4c93cf18', 'hex'),
        codecs.decode('41397eea', 'hex'),
        codecs.decode('082fef30', 'hex'),
        codecs.decode('66ef7655', 'hex'),
        codecs.decode('61c5938a', 'hex'),
        codecs.decode('33c083d4', 'hex'),
        codecs.decode('7256c032', 'hex'),
        codecs.decode('04e5b397', 'hex'),
        codecs.decode('2823443f', 'hex'),
        codecs.decode('2679dc69', 'hex'),
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
