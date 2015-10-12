AESCrypt
=======

___aescrypt___ is a small command line tool to encrypt/decrypt files and directories with the well-established AES-256-CBC algorithm.

Examples
--------

 * Encryption: `aescrypt encrypt foo.txt`
 * Decryption: `aescrypt decrypt foo.txt.aes`

Type `aescrypt --help` for more information on the usage.

Requirements
------------

Please install the following Python packages: [docopt](https://pypi.python.org/pypi/docopt), [pycrypto](https://pypi.python.org/pypi/pycrypto). You can do that by running:

`sudo pip install -r requirements.txt`

License
-------

**GNU General Public License (GPLv3)**, see `LICENSE.txt` for further details.
