#!/usr/bin/env python2
# -*- coding: UTF-8 -*-

'''
Usage:
	aescrypt.py encrypt <paths>...
	aescrypt.py decrypt <paths>...
	aescrypt.py (-h | --help | --version)

Options:
	-h --help	Shows the help screen.
	-v --version	Prints the version and exits.
	encrypt		Encryption mode.
	decrypt		Decryption mode.
'''

import os
import sys
import tarfile
import tempfile
import shutil

from docopt import docopt
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256, md5

class PasswordsDoNotMatch(Exception):
	pass

class DecryptionError(Exception):
	pass

pad = lambda x, n: x + (n - len(x) % n) * chr(n - len(x) % n)
unpad = lambda x: x[:-ord(x[len(x) - 1:])]

def encrypt(path, *args, **kwargs):

	if not os.path.exists(path):
		raise OSError('Path "%s" does not exist.' % path)

	if os.path.isdir(path):
		tarpath = '%s.tar' % path
		archive = tarfile.open(tarpath, 'w')
		archive.add(path)
		archive.close()
		shutil.rmtree(path)
		path, typeflag = tarpath, 'D'
	else:
		typeflag = 'F'

	if not kwargs.has_key('password') or not kwargs['password']:
		password1 = getpass('Enter a password: ')
		password2 = getpass('Confirm password: ')

		if password1 != password2:
			raise PasswordsDoNotMatch('Both passwords have to be identical.')
		else:
			kwargs['password'] = password1

	with open(path, 'rb') as f:
		content = f.read()

	key, iv, md5hash = sha256(kwargs['password']).digest(), get_random_bytes(AES.block_size), md5(content).digest()
	cipher = AES.new(key, AES.MODE_CBC, IV = iv)

	cryptopath = ('%s.aes' % path).replace('.tar', '')
	with open(cryptopath, 'wb') as f:
		ciphercontent = '%s%s%s' % (md5hash, typeflag, content)
		ciphertext = '%s%s' % (iv, cipher.encrypt(pad(ciphercontent, AES.block_size)))
		f.write(ciphertext)

	os.remove(path)
	return True

def decrypt(path, *args, **kwargs):

	if not os.path.exists(path):
		raise OSError('Path "%s" does not exist.' % path)

	if not kwargs.has_key('password') or not kwargs['password']:
		kwargs['password'] = getpass('Password: ')

	with open(path, 'rb') as f:
		content = f.read()

	key, iv = sha256(kwargs['password']).digest(), content[:16]
	cipher = AES.new(key, AES.MODE_CBC, IV = iv)

	plaincontent = unpad(cipher.decrypt(content[16:]))
	if not plaincontent:
		raise DecryptionError('Something went wrong. Is your password correct?')

	md5hash, typeflag, content = plaincontent[:16], plaincontent[16], plaincontent[17:]

	if typeflag == 'D':
		tarpath = tempfile.mktemp()
		with open(tarpath, 'wb') as f:
			f.write(content)

		if not tarfile.is_tarfile(tarpath):
			os.remove(tarpath)
			raise DecryptionError('Something went wrong. Is your password correct?')

		archive = tarfile.open(tarpath)
		archive.extractall()
		os.remove(path)

	else:

		if not md5(content).digest() == md5hash:
			raise DecryptionError('Something went wrong. Is your password correct?')
		else:
			plainpath = path.split('.aes')[0]
			with open(plainpath, 'wb') as f:
				f.write(content)
			os.remove(path)

	return True

if __name__ == '__main__':

	os.sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)))
	from aescrypt import __version__

	args = docopt(__doc__, version = __version__)

	if args['encrypt']:
		for p in args['<paths>']:
			try:
				encrypt(p)
			except OSError as e:
				sys.exit('%s Quitting.' % str(e))
			except PasswordsDoNotMatch as e:
				sys.exit('%s Quitting.' % str(e))

	if args['decrypt']:
		for p in args['<paths>']:
			try:
				decrypt(p)
			except OSError as e:
				sys.exit('%s Quitting.' % str(e))
			except DecryptionError as e:
				sys.exit('%s Quitting.' % str(e))
