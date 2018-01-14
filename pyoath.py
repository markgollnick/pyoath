#! /usr/bin/env python
# encoding=utf-8

"""
A Python OATH implementation.

OATH is the Initiative for Open Authentication - not to be confused with OAuth,
the Open Standard to *Authorization*, which is an entirely different paradigm.

PyOATH implements the HOTP Algorithm defined in RFC 4226, published in December
of 2005, and the TOTP Algorithm defined in RFC 6238, published in May of 2011.
It has been designed for both the client- and server-sides of two-factor
authentication systems.

Many of the variable names in this code were used because those were the names
used in those publications. Much of the documentation and many of the comments
in this file was taken straight from the RFC documentation as well.

Please read RFC 4226 and RFC 6238 for more information.
"""

from __future__ import unicode_literals
import argparse
import base64
import hashlib
import hmac
import os
import stat
import struct
import sys
import time
from os.path import expanduser, isfile, realpath


def _DT(String):
    """
    Dynamic Truncation of an HMAC-SHA-1 value.

        DT(String) // String = String[0]...String[19]
            Let OffsetBits be the low-order 4 bits of String[19]
            Offset = StToNum(OffsetBits) // 0 <= OffSet <= 15
            Let P = String[OffSet]...String[OffSet+3]
            Return the Last 31 bits of P

    :param String: An HMAC value. If HMAC-SHA-1, it's 160-bits (20-bytes) long.
    :type String: bytes
    :return: The 31-bit dynamically truncated HMAC value
    :rtype: int
    """
    OffsetBits = String[-1::1]
    Offset = ord(OffsetBits) & 0x0f
    P = String[Offset:Offset+4]
    Bits = _StToNum(P)

    # The reason for masking the most significant bit of P is to avoid
    # confusion about signed vs. unsigned modulo computations.  Different
    # processors perform these operations differently, and masking out the
    # signed bit removes all ambiguity.
    Bits &= 0x7fffffff

    return Bits


def _HMAC(K, C, Mode=hashlib.sha1):
    """
    Generate an HMAC value.

    The default mode is to generate an HMAC-SHA-1 value w/ the SHA-1 algorithm.

    :param K: shared secret between client and server.
            Each HOTP generator has a different and unique secret K.
    :type K: bytes
    :param C: 8-byte counter value, the moving factor.
            This counter MUST be synchronized between the HOTP generator
            (client) and the HOTP validator (server).
    :type C: bytes
    :param Mode: The algorithm to use when generating the HMAC value
    :type Mode: hashlib.sha1, hashlib.sha256, hashlib.sha512, or hashlib.md5
    :return: HMAC result. If HMAC-SHA-1, result is 160-bits (20-bytes) long.
    :rtype: bytes
    """
    return hmac.new(K, C, Mode).digest()


def _StToNum(S):
    """
    Convert S to a number.

    :param S: The (big-endian) bytestring to convert to an integer
    :type S: bytes
    :return: An integer representation of the bytestring (rightmost chr == LSB)
    :rtype: int
    """
    return struct.unpack('>L', S)[0]


def _Truncate(HS, Digit=6):
    """
    Convert an HMAC value into an HOTP value.

    NOTE:
    Implementations MUST extract a 6-digit code at a minimum and possibly
    7 and 8-digit code. Depending on security requirements, Digit = 7 or
    more SHOULD be considered in order to extract a longer HOTP value.

    :param HS: An HMAC bytestring. If HMAC-SHA-1, is 160-bits (20-bytes) long.
    :type HS: bytes
    :param Digit: Digits to extract from the dynamically truncated HMAC value
    :type Digit: int
    :return: The final HOTP value
    :rtype: str
    """
    # The Truncate function performs Step 2 and Step 3, i.e., the dynamic
    # truncation and then the reduction modulo 10^Digit. The purpose of
    # the dynamic offset truncation technique is to extract a 4-byte
    # dynamic binary code from a 160-bit (20-byte) HMAC-SHA-1 result.
    Snum = _DT(HS)  # Step 2+3
    D = Snum % (10 ** Digit)
    return str(D).zfill(Digit)


def HOTP(K, C, Digit=6, Mode=hashlib.sha1):
    """
    HOTP: An HMAC-Based One-Time Password Algorithm.

    The algorithm for this function is defined in RFC 4226, Section 5.3.

    :param K: shared secret between client and server.
            Each HOTP generator has a different and unique secret K.
    :type K: bytes
    :param C: the counter value (as an int), the moving factor.
            This counter MUST be synchronized between the HOTP generator
            (client) and the HOTP validator (server).
    :type C: int
    :param Digit: Digits to extract from the dynamically truncated HMAC value
    :type Digit: int
    :param Mode: The algorithm to use when generating the HMAC value
    :type Mode: hashlib.sha1, hashlib.sha256, hashlib.sha512, or hashlib.md5
    :return: An HMAC-Based One-Time Password
    :rtype: str
    """
    # We can describe the operations in 3 distinct steps:
    # Step 1: Generate an HMAC value
    C_bytestr = struct.pack('>Q', C)[-8:]  # Pack int C into an 8-byte string
    HS = _HMAC(K, C_bytestr, Mode)  # HS is a >= 20-byte string (if using SHA1)

    # Step 2: Generate a 4-byte string (Dynamic Truncation)
    # Step 3: Compute an HOTP value
    return _Truncate(HS, Digit)


def TOTP(K, X=30, Digit=6, Mode=hashlib.sha1):
    """
    TOTP: Time-Based One-Time Password Algorithm.

    This variant of the HOTP algorithm specifies the calculation of a
    one-time password value, based on a representation of the counter as
    a time factor.

    The algorithm for this function is defined in RFC 6238, Section 4.2.

    NOTE:
    TOTP implementations MAY use HMAC-SHA-256 or HMAC-SHA-512 functions,
    based on SHA-256 or SHA-512 [SHA2] hash functions, instead of the
    HMAC-SHA-1 function that has been specified for the HOTP computation
    in [RFC4226].

    :param K: shared secret between client and server.
            Each HOTP generator has a different and unique secret K.
    :type K: bytes
    :param X: represents the time step in seconds (default value X = 30)
    :type X: int
    :param Digit: Digits to extract from the dynamically truncated HMAC value
    :type Digit: int
    :param Mode: The algorithm to use when generating the HMAC value
    :type Mode: hashlib.sha1, hashlib.sha256, hashlib.sha512, or hashlib.md5
    :return: A Time-Based One-Time Password
    :rtype: str
    """
    unix_time = int(time.time())
    unix_step = int(unix_time / X)
    return HOTP(K, unix_step, Digit, Mode)


def _get_chmod_bits(file_path):
    """Get the CHMOD bits of a file."""
    s = os.stat(file_path)
    return s.st_mode & (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)


def _graceful_encode(s, encoding='utf-8', errors='strict'):
    """
    Convert a unicode string to a UTF-8 encoded bytestring.

    If the string is already a bytestring, return it unmodified.

    :param s: The string to encode as a bytestring
    :type s: str
    :param encoding: The encoding to use. Defaults to UTF-8.
    :type encoding: str
    :param errors: The error policy to employ when lossless encoding fails.
        Defaults to strict, which raises and exception. Can be set to replace
        for lossy encodes.
    :type errors: str
    :return: The string in encoded bytestring form,
            or the original input if the string was already a bytestring.
    :rtype: bytes
    """
    try:
        return s.encode(encoding=encoding, errors=errors)
    except (AttributeError, UnicodeDecodeError):
        if hasattr(s, 'startswith'):  # Already a bytestring
            return s
        raise
    except UnicodeEncodeError:
        sys.stderr.write("""\
Python 3 does not support arbitrary binary input supplied as command-line args.
If your key contains raw binary, write it to a file, protect its permissions
with, e.g., `chmod 600 secret.2fa`, and then pass the file path as an argument
to pyoath.
""")
        sys.exit(1)


def _parse_args(args):
    """Parse command-line arguments."""
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

    return parser.parse_args(args or sys.argv[1:])


def main(*args):
    """Program entry point for command-line use."""
    options = _parse_args(args)
    secret = options.secret
    secret_path = realpath(expanduser(secret))

    if isfile(secret_path):
        # Encourage good old-fashioned practices
        # with some good old-fashioned butt-kicking.
        mode = _get_chmod_bits(secret_path)
        if mode & 0o077 != 0:
            msg = """\
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@          WARNING: UNPROTECTED SECRET 2FA FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0%o for '%s' are too open.
It is required that your secret key files are NOT accessible by others.
This secret key will be ignored.
""" % (mode, secret_path)
            sys.stderr.write(msg)
            return 2

        with open(secret_path, 'rb') as f:
            secret = f.read()
            if options.google:
                contents = secret.decode('utf-8').strip().upper()
                secret = base64.b32decode(contents)

    secret = _graceful_encode(secret)

    if options.loop:
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
                return 0

    otp = TOTP(secret)
    sys.stdout.write(otp + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
