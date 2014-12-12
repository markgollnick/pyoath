#!/usr/bin/env python

"""
Python OATH (One-time AuTHentication) implementation.

This file implements HOTP as defined in RFC 4226, published December, 2005, and
TOTP as defined in RFC 6238, published May 2011.

Many of the variable names in this code were used because those were the names
used in those publications.  Much of the documentation and many of the comments
in this file was taken straight from the RFC documentation as well.

Please read the files rfc4226.txt and rfc6238.txt for more information.
"""

import hashlib
import hmac
import struct
import time


def _DT(String):
    """
    Dynamic Truncation of an HMAC-SHA-1 value.

        DT(String) // String = String[0]...String[19]
         Let OffsetBits be the low-order 4 bits of String[19]
         Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
         Let P = String[OffSet]...String[OffSet+3]
         Return the Last 31 bits of P

    @param String: An HMAC-SHA-1 value; a 20-byte string
    @type String: str
    @return: The dynamically truncated HMAC-SHA-1 value; a 31-bit/4-byte string
    @rtype: str
    """
    Offset = ord(String[-1]) & 0x0f
    P = String[Offset:Offset+4]
    Bits = map(ord, P)

    # The reason for masking the most significant bit of P is to avoid
    # confusion about signed vs. unsigned modulo computations.  Different
    # processors perform these operations differently, and masking out the
    # signed bit removes all ambiguity.
    Bits[0] = Bits[0] & 0x7f

    return ''.join(map(chr, Bits))


def _HMAC(K, C, Mode=hashlib.sha1):
    """
    Generate an HMAC value.

    The default mode is to generate an HMAC value using the SHA-1 algorithm.

    @param K: shared secret between client and server; each HOTP
              generator has a different and unique secret K.
    @type K: str
    @param C: 8-byte counter value, the moving factor.  This counter
              MUST be synchronized between the HOTP generator (client)
              and the HOTP validator (server).
    @type C: str
    @param Mode: The algorithm to use when generating the HMAC value
    @type Mode: hashlib.sha1, hashlib.sha256, hashlib.sha512, or hashlib.md5
    @return: HMAC result. If HMAC-SHA-1, result is a 160-bit (20-byte) string
    @rtype: str
    """
    return hmac.new(K, C, Mode).digest()


def _StToNum(S):
    """
    Convert S to a number.

    @param S: The bytestring to convert to an integer
    @type S: bytestring
    @return: An integer representation of the bytestring (rightmost chr == LSB)
    @rtype: int
    """
    Bytes = map(ord, S)
    Length = len(Bytes)
    return sum(Bytes[Length - 1 - i] << (8 * i) for i in range(Length))


def _Truncate(HS, Digit=6):
    """
    Convert an HMAC value into an HOTP value.

    NOTE:
    Implementations MUST extract a 6-digit code at a minimum and possibly
    7 and 8-digit code.  Depending on security requirements, Digit = 7 or
    more SHOULD be considered in order to extract a longer HOTP value.

    @param HS: An HMAC value. If HMAC-SHA-1, will be a 160-bit (20-byte) string
    @type HS: str
    @param Digit: Digits to extract from the dynamically truncated HMAC value
    @type Digit: int
    @return: The final HOTP value
    @rtype: str
    """
    # The Truncate function performs Step 2 and Step 3, i.e., the dynamic
    # truncation and then the reduction modulo 10^Digit.  The purpose of
    # the dynamic offset truncation technique is to extract a 4-byte
    # dynamic binary code from a 160-bit (20-byte) HMAC-SHA-1 result.

    Sbits = _DT(HS)  # Step 2
    Snum = _StToNum(Sbits)  # Step 3
    D = Snum % (10 ** Digit)
    return str(D).zfill(Digit)


def HOTP(K, C, Digit=6, Mode=hashlib.sha1):
    """
    HOTP: An HMAC-Based One-Time Password Algorithm.

    The algorithm for this function is defined in RFC 4226, Section 5.3.

    @param K: shared secret between client and server; each HOTP
              generator has a different and unique secret K.
    @type K: str
    @param C: the counter value (as an int), the moving factor.  This counter
              MUST be synchronized between the HOTP generator (client)
              and the HOTP validator (server).
    @type C: int
    @param Digit: Digits to extract from the dynamically truncated HMAC value
    @type Digit: int
    @param Mode: The algorithm to use when generating the HMAC value
    @type Mode: hashlib.sha1, hashlib.sha256, hashlib.sha512, or hashlib.md5
    @return: An HMAC-Based One-Time Password
    @rtype: str
    """
    # We can describe the operations in 3 distinct steps:

    # Step 1: Generate an HMAC value
    C_bytestr = struct.pack('!Q', C)  # Pack int C into an 8-byte string
    HS = _HMAC(K, C_bytestr, Mode)    # HS is a 20-byte string

    # Step 2: Generate a 4-byte string (Dynamic Truncation)
    # Step 3: Compute an HOTP value
    return _Truncate(HS, Digit)


def TOTP(K, X=30, Digit=6, Mode=hashlib.sha1):
    """
    TOTP: Time-Based One-Time Password Algorithm.

    This variant of the HOTP algorithm specifies the calculation of a
    one-time password value, based on a representation of the counter as
    a time factor.

    @param K: shared secret between client and server; each HOTP
              generator has a different and unique secret K.
    @type K: str
    @param X: represents the time step in seconds (default value X = 30)
    @type X: int
    @param Digit: Digits to extract from the dynamically truncated HMAC value
    @type Digit: int
    @param Mode: The algorithm to use when generating the HMAC value
    @type Mode: hashlib.sha1, hashlib.sha256, hashlib.sha512, or hashlib.md5
    @return: A Time-Based One-Time Password
    @rtype: str
    """
    unix_time = int(time.time())
    unix_step = unix_time / X
    return HOTP(K, unix_step, Digit, Mode)
