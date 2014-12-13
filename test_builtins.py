"""Unit tests for Python's built-in hashlib and hmac modules."""

from unittest import TestCase

import hashlib  # Unit Under Test
import hmac  # Unit Under Test


class HashLibSha1TestCase(TestCase):

    """
    These tests are taken straight out of RFC 3174.

    See Python's source code for more information.
    """

    def test_sha1_vector_1(self):
        data = b'abc'
        expect = 'a9993e364706816aba3e25717850c26c9cd0d89d'
        result = hashlib.sha1(data).hexdigest()
        self.assertEqual(expect, result, 'Your SHA-1 implementation is broken')

    def test_sha1_vector_2(self):
        data = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
        expect = '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
        result = hashlib.sha1(data).hexdigest()
        self.assertEqual(expect, result, 'Your SHA-1 implementation is broken')

    def test_sha1_vector_3(self):
        data = b'a' * 1000000
        expect = '34aa973cd4c4daa4f61eeb2bdbad27316534016f'
        result = hashlib.sha1(data).hexdigest()
        self.assertEqual(expect, result, 'Your SHA-1 implementation is broken')

    def test_sha1_vector_4(self):
        data = (b'01234567012345670123456701234567'
                b'01234567012345670123456701234567') * 10
        expect = 'dea356a2cddd90c7a7ecedc5ebb563934f460452'
        result = hashlib.sha1(data).hexdigest()
        self.assertEqual(expect, result, 'Your SHA-1 implementation is broken')


class HMACTestCase(TestCase):

    """
    These tests are taken straight out of RFC 2104.

    Python's hmac module also complies with the test vectors in RFC 4231.

    See Python's source code for more information.
    """

    def test_hmac_vector_1(self):
        key = b'\x0b' * 16
        data = b'Hi There'
        digest = '9294727a3638bb1c13f48ef8158bfc9d'
        result = hmac.new(key, data).hexdigest()
        self.assertEqual(digest, result, 'Your HMAC implementation is broken')

    def test_hmac_vector_2(self):
        key = b'Jefe'
        data = b'what do ya want for nothing?'
        digest = '750c783e6ab0b503eaa86e310a5db738'
        result = hmac.new(key, data).hexdigest()
        self.assertEqual(digest, result, 'Your HMAC implementation is broken')

    def test_hmac_vector_3(self):
        key = b'\xaa' * 16
        data = b'\xdd' * 50
        digest = '56be34521d144c88dbb8c733f0e8b3f6'
        result = hmac.new(key, data).hexdigest()
        self.assertEqual(digest, result, 'Your HMAC implementation is broken')
