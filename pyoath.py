#!/usr/bin/env python

"""
Python OATH (One-time AuTHentication) implementation.

This file implements HOTP as defined in RFC 4226, published December, 2005.

Many of the variable names in this code were used because those were the names
used in the publication.  Much of the documentation and many of the comments in
this file was taken straight from the RFC documentation as well.

Please read the file rfc4226.txt for more information.
"""

import hashlib
import hmac
import struct


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
    Offset = ord(String[19]) & 0x0f
    P = String[Offset:Offset+4]
    Bits = map(ord, P)

    # The reason for masking the most significant bit of P is to avoid
    # confusion about signed vs. unsigned modulo computations.  Different
    # processors perform these operations differently, and masking out the
    # signed bit removes all ambiguity.
    Bits[0] = Bits[0] & 0x7f

    return ''.join(map(chr, Bits))


def _HMAC_SHA1(K, C):
    """
    Generate an HMAC-SHA-1 value.

    @param K: shared secret between client and server; each HOTP
              generator has a different and unique secret K.
    @type K: str
    @param C: 8-byte counter value, the moving factor.  This counter
              MUST be synchronized between the HOTP generator (client)
              and the HOTP validator (server).
    @type C: str
    @return: HMAC-SHA-1 result; a 160-bit (20-byte) string
    @rtype: str
    """
    return hmac.new(K, C, hashlib.sha1).digest()


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
    Convert an HMAC-SHA-1 value into an HOTP value.

    The algorithm for this function is defined in RFC 4226, Section 5.3.

    NOTE:
    Implementations MUST extract a 6-digit code at a minimum and possibly
    7 and 8-digit code.  Depending on security requirements, Digit = 7 or
    more SHOULD be considered in order to extract a longer HOTP value.

    @param HS: An HMAC-SHA-1 value; a 160-bit (20-byte) string
    @type HS: str
    @param Digit: Digits to extract from the dynamically truncated HMAC value
    @type Digit: int
    @return: The final HOTP value
    @rtype: int
    """
    # The Truncate function performs Step 2 and Step 3, i.e., the dynamic
    # truncation and then the reduction modulo 10^Digit.  The purpose of
    # the dynamic offset truncation technique is to extract a 4-byte
    # dynamic binary code from a 160-bit (20-byte) HMAC-SHA-1 result.

    Sbits = _DT(HS)  # Step 2
    Snum = _StToNum(Sbits)  # Step 3
    D = Snum % (10 ** Digit)
    return D


def HOTP(K, C, Digit=6):
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
    """
    # We can describe the operations in 3 distinct steps:

    # Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS
    # is a 20-byte string

    # Step 2: Generate a 4-byte string (Dynamic Truncation)
    # Let Sbits = DT(HS)   //  DT, defined below,
    #                      //  returns a 31-bit string

    # Step 3: Compute an HOTP value
    # Let Snum  = StToNum(Sbits)   // Convert S to a number in
    #                                  0...2^{31}-1
    # Return D = Snum mod 10^Digit //  D is a number in the range
    #                                  0...10^{Digit}-1

    C_bytestr = struct.pack('!Q', C)  # Pack int into an 8-byte string
    HS = _HMAC_SHA1(K, C_bytestr)  # Step 1
    return _Truncate(HS, Digit)
