#!/usr/bin/env python

"""
A Python OATH implementation.

OATH is the Initiative for Open Authentication - not to be confused with OAuth,
the Open Standard to *Authorization*, which is an entirely different paradigm.

Pyoath implements the HOTP Algorithm defined in RFC 4226, published in December
of 2005, and the TOTP Algorithm defined in RFC 6238, published in May of 2011.
It has been designed for both the client- and server-sides of two-factor
authentication systems.

Many of the variable names in this code were used because those were the names
used in those publications. Much of the documentation and many of the comments
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

    @param String: An HMAC value. If HMAC-SHA-1, is 160-bits (20-bytes) long.
    @type String: bytes
    @return: The dynamically truncated HMAC value. 31-bits (4-bytes) long.
    @rtype: bytes
    """
    OffsetBits = String[-1] if isinstance(String[-1], str) else chr(String[-1])
    Offset = ord(OffsetBits) & 0x0f
    P = String[Offset:Offset+4]
    Bits = list(map(lambda x: ord(x) if isinstance(x, str) else x, P))

    # The reason for masking the most significant bit of P is to avoid
    # confusion about signed vs. unsigned modulo computations.  Different
    # processors perform these operations differently, and masking out the
    # signed bit removes all ambiguity.
    Bits[0] = Bits[0] & 0x7f

    return ''.join(map(chr, Bits)) if str == bytes else bytes(Bits)  # Py 3


def _HMAC(K, C, Mode=hashlib.sha1):
    """
    Generate an HMAC value.

    The default mode is to generate an HMAC-SHA-1 value w/ the SHA-1 algorithm.

    @param K: shared secret between client and server; each HOTP
              generator has a different and unique secret K.
    @type K: bytes
    @param C: 8-byte counter value, the moving factor.  This counter
              MUST be synchronized between the HOTP generator (client)
              and the HOTP validator (server).
    @type C: bytes
    @param Mode: The algorithm to use when generating the HMAC value
    @type Mode: hashlib.sha1, hashlib.sha256, hashlib.sha512, or hashlib.md5
    @return: HMAC result. If HMAC-SHA-1, result is 160-bits (20-bytes) long.
    @rtype: bytes
    """
    return hmac.new(K, C, Mode).digest()


def _StToNum(S):
    """
    Convert S to a number.

    @param S: The bytestring to convert to an integer
    @type S: bytes
    @return: An integer representation of the bytestring (rightmost chr == LSB)
    @rtype: int
    """
    Length = len(S)
    Bytes = list(map(lambda x: ord(x) if isinstance(x, str) else x, S))
    return sum(Bytes[Length - 1 - i] << (8 * i) for i in range(Length))


def _Truncate(HS, Digit=6):
    """
    Convert an HMAC value into an HOTP value.

    NOTE:
    Implementations MUST extract a 6-digit code at a minimum and possibly
    7 and 8-digit code.  Depending on security requirements, Digit = 7 or
    more SHOULD be considered in order to extract a longer HOTP value.

    @param HS: An HMAC bytestring. If HMAC-SHA-1, is 160-bits (20-bytes) long.
    @type HS: bytes
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

    NOTE:
    TOTP implementations MAY use HMAC-SHA-256 or HMAC-SHA-512 functions,
    based on SHA-256 or SHA-512 [SHA2] hash functions, instead of the
    HMAC-SHA-1 function that has been specified for the HOTP computation
    in [RFC4226].

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
    unix_step = int(unix_time / X)
    return HOTP(K, unix_step, Digit, Mode)


if __name__ == '__main__':
    import argparse
    import base64
    import os
    import stat
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    arg = parser.add_argument

    arg('secret',
        help='shared secret file between client and server',
        type=str)

    arg('--google',
        help='Google Authenticator mode (assumes secret is encoded in base32)',
        action='store_true',
        required=False)

    arg('--loop',
        help='start an authenticator instance that will continue until killed',
        action='store_true',
        required=False)

    args = parser.parse_args()

    resolve = lambda *x: os.path.realpath(os.path.expanduser(os.path.join(*x)))

    def chmod(file_path):
        """Get the CHMOD bits of a file."""
        s = os.stat(file_path)
        return s.st_mode & (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

    secret = args.secret
    secret_path = resolve(secret)

    if os.path.isfile(secret_path):
        # Encourage good old-fashioned practices
        # with some good old-fashioned butt-kicking.
        mode = chmod(secret_path)
        if mode & 0o077 != 0:
            msg = """\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@          WARNING: UNPROTECTED SECRET KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0%o for '%s' are too open.
It is required that your secret key files are NOT accessible by others.
This secret key will be ignored.
""" % (mode, secret_path)
            sys.stdout.write(msg)
            sys.exit(1)

        with open(secret_path, 'rb') as f:
            data = f.read()
            secret = base64.b32decode(data.upper()) if args.google else data

    if args.loop:
        last_otp = None
        counter = 30
        sys.stdout.write("""
Authenticator Started!
:----------------------------:--------:
:       Code Wait Time       :  Code  :
:----------------------------:--------:
""")
        while True:
            try:
                this_otp = TOTP(secret)
                counter -= 1
                if this_otp == last_otp:
                    sys.stdout.write('.')
                else:
                    last_otp = this_otp
                    sys.stdout.write('+' * counter + ': %s :\n' % this_otp)
                    counter = 30
                sys.stdout.flush()
                time.sleep(1)
            except KeyboardInterrupt:
                sys.exit(0)

    otp = TOTP(secret)
    sys.stdout.write(otp + '\n')
