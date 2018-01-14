"""Unit tests for Python's built-in hashlib and hmac modules."""

import hashlib  # Unit Under Test
import hmac  # Unit Under Test

from nose.tools import assert_equal


def test_hashlib_sha1():
    def test(supply, factor, expect):
        actual = hashlib.sha1(supply * factor).hexdigest()
        assert_equal(expect, actual)

    # These tests are taken straight out of RFC 3174.
    scenarios = [(
        b'abc', 1,
        'a9993e364706816aba3e25717850c26c9cd0d89d',
    ), (
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', 1,
        '84983e441c3bd26ebaae4aa1f95129e5e54670f1',
    ), (
        b'a', 1000000,
        '34aa973cd4c4daa4f61eeb2bdbad27316534016f',
    ), (
        b'01234567012345670123456701234567', 20,
        'dea356a2cddd90c7a7ecedc5ebb563934f460452',
    )]

    for supply, factor, expect in scenarios:
        yield test, supply, factor, expect


def test_hmac_md5():
    def test(key, factor_1, msg, factor_2, expect):
        actual = hmac.new(key * factor_1, msg * factor_2).hexdigest()
        assert_equal(expect, actual)

    # These tests are taken straight out of RFC 2104.
    scenarios = [(
        b'\x0b', 16,
        b'Hi There', 1,
        '9294727a3638bb1c13f48ef8158bfc9d',
    ), (
        b'Jefe', 1,
        b'what do ya want for nothing?', 1,
        '750c783e6ab0b503eaa86e310a5db738',
    ), (
        b'\xaa', 16,
        b'\xdd', 50,
        '56be34521d144c88dbb8c733f0e8b3f6',
    )]

    for key, factor_1, msg, factor_2, expect in scenarios:
        yield test, key, factor_1, msg, factor_2, expect
