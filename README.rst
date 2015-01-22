
======
pyoath
======

.. image:: https://travis-ci.org/markgollnick/pyoath.svg?branch=master
    :target: https://travis-ci.org/markgollnick/pyoath
    :alt: Build Status

.. image:: https://coveralls.io/repos/markgollnick/pyoath/badge.svg?branch=master
    :target: https://coveralls.io/r/markgollnick/pyoath?branch=master
    :alt: Coverage Status

|

.. image:: https://raw.githubusercontent.com/markgollnick/pyoath/master/padlocks.png
    :alt: Two-Factor Authentication

A Python OATH implementation.

OATH is the `Initiative for Open Authentication`_ — not to be confused with
OAuth, the Open Standard to *Authorization*, which is an entirely different
paradigm.

.. _Initiative for Open Authentication: http://www.openauthentication.org/

Pyoath implements the HOTP Algorithm defined in `RFC 4226`_, published in
December of 2005, and the TOTP Algorithm defined in `RFC 6238`_, published in
May of 2011. It has been designed for both the client- and server-sides of
two-factor authentication systems.

.. _RFC 4226: http://www.ietf.org/rfc/rfc4226.txt
.. _RFC 6238: http://www.ietf.org/rfc/rfc6238.txt


Requirements
------------
    
* Python >= 2.6, 2.7, 3.2, 3.3, 3.4…


Installation
------------

**For Users**::

    pip install pyoath

**For Developers**::

    git clone git@github.com:markgollnick/pyoath.git
    cd pyoath
    python setup.py build install
    # Alternatively...
    python setup.py sdist
    pip install dist/pyoath-*.tar.gz


Usage
-----

Once installed, you can use it as a script (that is, on the client-side)…

::

    $ pyoath -h
    usage: pyoath.py [-h] [--google] [--loop] secret

    positional arguments:
      secret      shared secret [file] between client and server

    optional arguments:
      -h, --help  show this help message and exit
      --google    Google Authenticator mode (assumes secret is encoded in base32)
      --loop      start an authenticator instance that will continue until killed

…or, you can use it as a library (that is, on the server-side)::

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


Extras
------

Since most services provide their users with two-factor secret keys in the form
of scannable `QR Codes`_, you might be interested in the following utilities:

- `Open Source QR Code Library`_, a CLI tool written in Java to read QR Codes
- pyqrcode_, a Python library offering bindings based on the above Java tool
- BarCapture_, a GUI tool written in Java to extract the data from QR Codes

.. _QR Codes: https://en.wikipedia.org/wiki/QR_code
.. _Open Source QR Code Library: http://qrcode.sourceforge.jp/
.. _pyqrcode: http://pyqrcode.sourceforge.net/
.. _BarCapture: http://jaxo-systems.com/solutions/barcapture/


Acknowledgments
---------------

- Special thanks to James Cuff for the `Java-based Google Authenticator Desktop
  Client`__, which inspired this project.
- Special thanks to Yusuke Yanbe for the `Open Source QR Code Library`_.
- Special thanks to Pierre G. Richard of `Jaxo Systems`_ for the BarCapture_
  tool, and for his work with barcode interpretation on mobile platforms.
- Special thanks to OpenSSH_ for the bold notice about poor file access bits.
- Special thanks to AJ__ for the padlock__ icons__.

__ http://blog.jcuff.net/2011/02/cli-java-based-google-authenticator.html
.. _Jaxo Systems: http://jaxo-systems.com/
.. _OpenSSH: http://www.openssh.com/
__ https://openclipart.org/user-detail/AJ
__ https://openclipart.org/detail/17931/padlock-by-aj
__ https://openclipart.org/detail/33553/open-padlock-by-anonymous


Disclaimer
----------

THIS IS A PROOF-OF-CONCEPT.

It is ***NOT*** recommended that you store your two-factor authentication
secret keys on your hard-disk, as this significantly recudes most semblances of
security that two-factor authentication provides. The whole point of two-factor
authentication is that a would-be attacker must jump through *two* separate
hoops:

1. (S)he must crack (or glean through hacking, social engineering, etc.) your
   password or passphrase to the system or service.
2. (S)he must gain access to the device containing your two-factor secret key,
   which is usually your mobile phone, or a key fob which you should have on
   your person at all times.

Since it’s likely that the computer you use to log into your other systems and
online services has its own form of password caching and/or storage, storing a
second secret key somewhere on the machine nullifies this idea of device
separation, and makes it that much easier for a would-be attacker to gain
access to things they shouldn’t.

As it says in the license:

| THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
| IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
| FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
| SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
| FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
| ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
| DEALINGS IN THE SOFTWARE.

In other words, use this software — wisely, or unwisely — at YOUR OWN RISK.

Now that *that’s* out of the way… however you choose to go about it, you should
still

Two__.

Factor__.

Everything__.

__ https://medium.com/@N/how-i-lost-my-50-000-twitter-username-24eb09e026dd
__ http://arstechnica.com/security/2014/03/after-n-hijack-software-engineer-starts-two-factor-authentication-directory/
__ http://socialcustomer.com/2014/04/how-to-enable-two-factor-authentication-on-50-top-websites-including-facebook-twitter-and-others.html


License
-------

Boost Software License, Version 1.0: <http://www.boost.org/LICENSE_1_0.txt>
