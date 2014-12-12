"""Unit tests for Python's built-in hmac module."""

from unittest import TestCase

import hmac  # Unit Under Test


class HMACTestCase(TestCase):

    """
    These tests are taken straight out of RFC 2104.

    Python's hmac module also complies with the test vectors in RFC 4231.

    See Python's source code for more information.
    """

    def test_hmac_vector_1(self):
        key = '\x0b' * 16
        data = 'Hi There'
        digest = '9294727a3638bb1c13f48ef8158bfc9d'
        result = hmac.new(key, data).hexdigest()
        self.assertEqual(digest, result)

    def test_hmac_vector_2(self):
        key = 'Jefe'
        data = 'what do ya want for nothing?'
        digest = '750c783e6ab0b503eaa86e310a5db738'
        result = hmac.new(key, data).hexdigest()
        self.assertEqual(digest, result)

    def test_hmac_vector_3(self):
        key = '\xaa' * 16
        data = '\xdd' * 50
        digest = '56be34521d144c88dbb8c733f0e8b3f6'
        result = hmac.new(key, data).hexdigest()
        self.assertEqual(digest, result)
