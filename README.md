pyoath
======

[![Build Status](https://travis-ci.org/markgollnick/pyoath.svg?branch=master)](https://travis-ci.org/markgollnick/pyoath)
[![Coverage Status](https://img.shields.io/coveralls/markgollnick/pyoath.svg)](https://coveralls.io/r/markgollnick/pyoath?branch=master)

![Two-Factor Authentication](https://raw.githubusercontent.com/markgollnick/pyoath/master/2fa-padlocks.png)

A Python OATH (One-time Authentication) implementation.

Pyoath implements HOTP as defined in RFC 4226, published December, 2005, and
TOTP as defined in RFC 6238, published May 2011, and has been designed to be
used on both the client- and server-sides of two-factor authentication systems.


Requirements
------------

* Python >= 2.6, 2.7, 3.2, 3.3, 3.4…


Installation
------------

**For Users:**

    pip install git+ssh://git@github.com/markgollnick/pyoath@v1.0.0#egg=pyoath-1.0.0

**For Developers:**

    git clone git@github.com:markgollnick/pyoath.git
    cd pyoath
    python setup.py build install
    # Alternatively...
    python setup.py sdist
    pip install dist/pyoath-1.0.0.tar.gz


Usage
-----

Once installed, you can use it as a script (that is, on the client-side)…

    $ pyoath ~/.secrets/secret.key
    123456
    $ pyoath ~/.secrets/secret.key --loop
    
    Authenticator Started!
    :----------------------------:--------:
    :       Code Wait Time       :  Code  :
    :----------------------------:--------:
    +++++++++++++++++++++++++++++: 123456 :
    ....................+++++++++: 234567 :
    .............................: 345678 :
    .........^C
    $ 

…or, you can use it as a library (that is, on the server-side):

    >>> import pyoath
    >>> pyoath.HOTP(b'secret', 0)
    '814628'
    >>> pyoath.HOTP(b'secret', 1, Digit=8)
    '28533881'
    >>> pyoath.TOTP(b'secret')
    '123456'
    >>> pyoath.TOTP(b'secret', Digit=8)
    '12345678'
    >>> import hashlib
    >>> pyoath.TOTP(b'secret', Digit=8, Mode=hashlib.sha512)
    '87654321'


Acknowledgments
---------------

- Special thanks to OpenSSH for the bold notice about poor file access bits:
  <http://www.openssh.com/>
- Special thanks to James Cuff for the
  [Java-based Google Authenticator Desktop Client][2], which inspired this
  project.
- Special thanks to [AJ][] for [padlock][open] [icons][closed].

[1]: http://blog.jcuff.net/2011/02/cli-java-based-google-authenticator.html
[AJ]: https://openclipart.org/user-detail/AJ
[open]: https://openclipart.org/detail/33553/open-padlock-by-anonymous
[closed]: https://openclipart.org/detail/17931/padlock-by-aj


Disclaimer
----------

THIS IS A PROOF-OF-CONCEPT.

It is ***NOT*** recommended that you store your two-factor authentication
secret keys on your hard-disk, as this COMPLETELY OBLITERATES most semblances
of security that two-factor authentication provides.  The whole point of
two-factor authentication is that a would-be attacker must jump through *two*
separate hoops:

1. (S)he must crack (or glean through hacking, social engineering, etc.) your
   password or passphrase to the system or service.
2. (S)he must gain access to the device with your two-factor secret key, which
   is usually your mobile phone, or a key fob which you should have on your
   person at all times.

Since it is likely that the computer you use to log into your other systems and
online services has its own form of password caching and/or storage, (unless
you’ve disabled it, which is a good idea if you’d like a bit of added security)
storing a second secret key somewhere on the machine nullifies this idea of key
separation, and makes it that much easier for a would-be attacker to gain
access to things they shouldn’t.

As it says in the license:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

In other words, use this software — wisely, or unwisely — at YOUR OWN RISK.


License
-------

Boost Software License, Version 1.0: <http://www.boost.org/LICENSE_1_0.txt>
