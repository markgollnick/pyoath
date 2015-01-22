"""Unit tests for the pyoath module."""

import struct
from unittest import TestCase

from mock import patch, call

import pyoath  # Unit Under Test

try:
    import builtins  # Python >= 3.x
except ImportError:  # pragma: no cover
    import __builtin__ as builtins  # Python < 3.x

    class bytes(builtins.bytes):
        def __new__(cls, x, encoding='ascii'):
            return super(bytes, cls).__new__(cls, x.encode(encoding))

        @classmethod
        def fromhex(cls, x):
            return x.decode('hex')


class HMACSHA1TestCase(TestCase):

    """
    These tests are taken straight out of RFC 4226.

    See that RFC document for more information.
    """

    def test_hmac_sha1_vectors_1_thru_10(self):
        secret = b'12345678901234567890'
        expect = [
            bytes.fromhex('cc93cf18508d94934c64b65d8ba7667fb7cde4b0'),
            bytes.fromhex('75a48a19d4cbe100644e8ac1397eea747a2d33ab'),
            bytes.fromhex('0bacb7fa082fef30782211938bc1c5e70416ff44'),
            bytes.fromhex('66c28227d03a2d5529262ff016a1e6ef76557ece'),
            bytes.fromhex('a904c900a64b35909874b33e61c5938a8e15ed1c'),
            bytes.fromhex('a37e783d7b7233c083d4f62926c7a25f238d0316'),
            bytes.fromhex('bc9cd28561042c83f219324d3c607256c03272ae'),
            bytes.fromhex('a4fb960c0bc06e1eabb804e5b397cdc4b45596fa'),
            bytes.fromhex('1b3c89f65e6c9e883012052823443f048b4332db'),
            bytes.fromhex('1637409809a679dc698207310c8c7fc07290d9e5')]
        for count in range(len(expect)):
            result = pyoath._HMAC(secret, struct.pack('!Q', count))
            self.assertEqual(expect[count], result)


class DTTestCase(TestCase):

    """
    These tests are taken straight out of RFC 4226.

    See that RFC document for more information.
    """

    def test_dynamic_truncation_vectors_1_thru_10(self):
        secret = b'12345678901234567890'
        expect = [
            bytes.fromhex('4c93cf18'),
            bytes.fromhex('41397eea'),
            bytes.fromhex('082fef30'),
            bytes.fromhex('66ef7655'),
            bytes.fromhex('61c5938a'),
            bytes.fromhex('33c083d4'),
            bytes.fromhex('7256c032'),
            bytes.fromhex('04e5b397'),
            bytes.fromhex('2823443f'),
            bytes.fromhex('2679dc69')]
        for count in range(len(expect)):
            hmac_sha1 = pyoath._HMAC(secret, struct.pack('!Q', count))
            result = pyoath._DT(hmac_sha1)
            self.assertEqual(expect[count], result)


class HOTPTestCase(TestCase):

    """
    These tests are taken straight out of RFC 4226.

    See that RFC document for more information.
    """

    def test_hotp_vectors_1_thru_10(self):
        secret = b'12345678901234567890'
        expect = [
            '755224',
            '287082',
            '359152',
            '969429',
            '338314',
            '254676',
            '287922',
            '162583',
            '399871',
            '520489']
        for count in range(len(expect)):
            result = pyoath.HOTP(secret, count)
            self.assertEqual(expect[count], result)


class TOTPTestCase(TestCase):

    """
    These tests are taken straight out of RFC 6238.

    See that RFC document for more information.
    """

    def setUp(self):
        self.addCleanup(patch.stopall)
        self.time = patch.object(pyoath.time, 'time').start()
        self.time.side_effect = [
            59,          # 1970-01-01 00:00:59 +0000
            1111111109,  # 2005-03-18 01:58:29 +0000
            1111111111,  # 2005-03-18 01:58:31 +0000
            1234567890,  # 2009-02-13 23:31:30 +0000
            2000000000,  # 2033-05-18 03:33:20 +0000
            20000000000  # 2603-10-11 11:33:20 +0000
        ]

    @patch.object(pyoath, 'HOTP')
    def test_totp_time_vectors(self, hotp):
        expect = [
            int('0000000000000001', 16),
            int('00000000023523ec', 16),
            int('00000000023523ed', 16),
            int('000000000273ef07', 16),
            int('0000000003f940aa', 16),
            int('0000000027bc86aa', 16)]
        calls = []
        for i in range(len(expect)):
            pyoath.TOTP('secret')
            calls.append(call('secret', expect[i], 6, pyoath.hashlib.sha1))
        self.assertTrue(hotp.called)
        self.assertEqual(len(expect), hotp.call_count)
        hotp.assert_has_calls(calls)

    def test_totp_sha1_vectors(self):
        secret = b'1234567890' * 2  # 20 bytes
        expect = [
            '94287082',
            '07081804',
            '14050471',
            '89005924',
            '69279037',
            '65353130']
        for i in range(len(expect)):
            result = pyoath.TOTP(secret, Digit=8)
            self.assertEqual(expect[i], result)

    def test_totp_sha256_vectors(self):
        secret = (b'1234567890' * 3) + b'12'  # 32 bytes for SHA-256
        expect = [
            '46119246',
            '68084774',
            '67062674',
            '91819424',
            '90698825',
            '77737706']
        for i in range(len(expect)):
            result = pyoath.TOTP(secret, Digit=8, Mode=pyoath.hashlib.sha256)
            self.assertEqual(expect[i], result)

    def test_totp_sha512_vectors(self):
        secret = (b'1234567890' * 6) + b'1234'  # 64 bytes for SHA-512
        expect = [
            '90693936',
            '25091201',
            '99943326',
            '93441116',
            '38618901',
            '47863826']
        for i in range(len(expect)):
            result = pyoath.TOTP(secret, Digit=8, Mode=pyoath.hashlib.sha512)
            self.assertEqual(expect[i], result)
