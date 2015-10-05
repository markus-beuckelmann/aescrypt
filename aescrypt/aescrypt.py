#!/usr/bin/env python2
# -*- coding: UTF-8 -*-

import os
import sys
import tarfile
import tempfile
import shutil

from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256, md5

class PasswordsDoNotMatch(Exception):
	pass

pad = lambda x, n: x + (n - len(x) % n) * chr(n - len(x) % n)

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
