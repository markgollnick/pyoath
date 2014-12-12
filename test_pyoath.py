"""Unit tests for the pyoath module."""

import struct
from unittest import TestCase


import pyoath  # Unit Under Test


class HMACSHA1TestCase(TestCase):

    """
    These tests are taken straight out of RFC 4226.

    See that RFC document for more information.
    """

    def test_hmac_sha1_vectors_1_thru_10(self):
        secret = '12345678901234567890'
        expect = [
            'cc93cf18508d94934c64b65d8ba7667fb7cde4b0'.decode('hex'),
            '75a48a19d4cbe100644e8ac1397eea747a2d33ab'.decode('hex'),
            '0bacb7fa082fef30782211938bc1c5e70416ff44'.decode('hex'),
            '66c28227d03a2d5529262ff016a1e6ef76557ece'.decode('hex'),
            'a904c900a64b35909874b33e61c5938a8e15ed1c'.decode('hex'),
            'a37e783d7b7233c083d4f62926c7a25f238d0316'.decode('hex'),
            'bc9cd28561042c83f219324d3c607256c03272ae'.decode('hex'),
            'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa'.decode('hex'),
            '1b3c89f65e6c9e883012052823443f048b4332db'.decode('hex'),
            '1637409809a679dc698207310c8c7fc07290d9e5'.decode('hex')]
        for count in range(len(expect)):
            result = pyoath._HMAC(secret, struct.pack('!Q', count))
            self.assertEqual(expect[count], result)


class DTTestCase(TestCase):

    """
    These tests are taken straight out of RFC 4226.

    See that RFC document for more information.
    """

    def test_dynamic_truncation_vectors_1_thru_10(self):
        secret = '12345678901234567890'
        expect = [
            '4c93cf18'.decode('hex'),
            '41397eea'.decode('hex'),
            '082fef30'.decode('hex'),
            '66ef7655'.decode('hex'),
            '61c5938a'.decode('hex'),
            '33c083d4'.decode('hex'),
            '7256c032'.decode('hex'),
            '04e5b397'.decode('hex'),
            '2823443f'.decode('hex'),
            '2679dc69'.decode('hex')]
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
        secret = '12345678901234567890'
        expect = [
            755224,
            287082,
            359152,
            969429,
            338314,
            254676,
            287922,
            162583,
            399871,
            520489]
        for count in range(len(expect)):
            result = pyoath.HOTP(secret, count)
            self.assertEqual(expect[count], result)
