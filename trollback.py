#!/usr/bin/env python
# -*- coding: latin-1 -*-
#█▀▀▀▀█▀▀▀▀▀██▀▀▀▀██▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀▓▒▀▀▀▀▀▀▀▀▀▀█▓▀ ▀▀▀██▀▀▀▀▀▀▀▀▀▓▓▀▀▀▀▀▀▀▀▀▌
#▌▄██▌ ▄▓██▄ ▀▄█▓▄▐ ▄▓█▓▓▀█ ▄▓██▀▓██▓▄ ▌▄█▓█▀███▓▄ ▌▄█▓█ ▀ ▄▓██▀▓██▓▄ ▄█▓█▀███▄■
#▌▀▓█▓▐▓██▓▓█ ▐▓█▓▌▐▓███▌■ ▒▓██▌ ▓██▓▌▐▓▒█▌▄ ▓██▓▌ ▐▓▒█▌▐ ▒▓██▌  ▓██▓▌▓▒█▌ ▓█▓▌
#▐▓▄▄▌░▓▓█▓▐▓▌ █▓▓▌░▓▓█▓▄▄ ▓▓██▓▄▄▓█▓▓▌░▓█▓ █ ▓█▓▓▌░▓█▓ ▒ ▓▓██▓▄▄▓█▓▓▌▓█▓ ░ ▓█▓▓
#▐▓▓█▌▓▓▓█▌ █▓▐██▓▌▐▓▒▓▌ ▄ ▐░▓█▌▄ ▀▀▀ ▐▓▓▓ ▐▌ ▀▀▀  ▐▓▓▓▄▄ ▐░▓█▌ ▄ ▀▀▀ ▓▓▓ ░ ██▓▓
#▐▓▓▓█▐▓▒██ ██▓▓▓▌▐▓▓██  █▌▐▓▓▒▌▐ ███░▌▐▓▓▒▌▐ ███░▌ ▐▓▓▒▌ ▐▓▓▒▌▀ ███░▌▓▓▒▌ ███░
# ▒▓▓█▌▒▓▓█▌ ▐▓█▒▒  ▒▓██▌▐█ ▒▓▓█ ▐█▓▒▒ ▒▒▓█  ▐█▓▒▒  ▒▒▓█ ▓▌▒▓▓█ ▐█▓▒▒ ▒▒▓█ ▐█▓▒▌
#▌ ▒▒░▀ ▓▒▓▀  ▀░▒▓ ▐▌ ▓▓▓▀ █ █▒▓▀▀░█▓ ▄▌ ▒▒▓▀▀░█▓ ▄▌ ▒▒▓▀▀ █▒▓▀▀░█▓ ▒▒▓▀▀░█▀
#█▄ ▀ ▄▄ ▀▄▄▀■ ▀ ▀▓█▄ ▀ ▄█▓█▄ ▀ ▓▄▄▄▄▄█▀ ▄▀ ▄▄▄▄▄▄█▓▄ ▀ ▄▄█▓▄▀ ▄▓▄█▄▀ ▄▄▄█▌
#
# Copyright (C) 2015 Jonathan Racicot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
# </copyright>
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>
# <summary>Allows to base64 encode strings and file contents 
# using a custom alphabet and padding character.</summary>
#//////////////////////////////////////////////////////////
#
#//////////////////////////////////////////////////////////
# Program Information
#
PROGRAM_NAME = "Trollback"
PROGRAM_DESC = "Counter-Throwback Application"
PROGRAM_USAGE = "%(prog)s"

__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////
# Imports Statements
#
import os
import re
import sys
import base64
import random
import string
import urllib
import httplib
import argparse
import traceback
import subprocess
from urlparse import urlparse
#//////////////////////////////////////////////////////////
# Constants and global variables
#
PRIV_USER = "0"
PRIV_ADMIN = "1"

POST_RESP_KEY = "pk"
POST_RESP_DATA = "res"
POST_URI = "uri"
POST_HOSTNAME = "hn"
POST_CRYPT_KEY = "crypto-key"
POST_AUTH_KEY = "enc"
POST_IPADDR = "num"
POST_PRIV = "pp"
POST_TBVERS = "vn"
POST_DATA = "pd"
POST_MACHINE_ID = "id"
POST_CC = "comcode"
POST_XOR = "xorkey"

HDR_UA = "User-Agent"
HDR_PRAGMA = "Pragma"

COMMAND_DELIM = "&"

RANDOM_VAL = "rnd"
DEFAULT_HOSTNAME = "Home"
DEFAULT_TB_VERS = "2.50"
DEFAULT_UA = "Mozilla/4.0"
DEFAULT_CRYPTO_KEY = "ZAQwsxcde321"
DEFAULT_AUTH_KEY = "123spec!alk3y456"
DEFAULT_STR_XOR_KEY = "Q"
NO_CACHE = "no-cache"

TbStringIndicators = ["Throwback", "INJECTION FAILED"]
TbFileExtensions = ["exe", "dll"]
#
#//////////////////////////////////////////////////////////	
# Argument Parser Declaration
#
usage = PROGRAM_USAGE
parser = argparse.ArgumentParser(
	usage=usage, 
	prog=PROGRAM_NAME, 
	version="%(prog)s "+__version__, 
	description=PROGRAM_DESC)
c2_options = parser.add_argument_group("C2 Server Options", "Options to communicate with C2 server")	
c2_options.add_argument("-t", "--target", 
	dest="target_uri", 
	help="URL of the C2 server to target.")
c2_options.add_argument("-k", "--crypto-key", 
	dest="crypto_key", 
	default=DEFAULT_CRYPTO_KEY,
	help="RC4 crypto key used by the server.")
c2_options.add_argument("-a", "--post-auth", 
	dest="postauth_key", 
	default=DEFAULT_AUTH_KEY,
	help="POST authentification key for requests to the server.")	
c2_options.add_argument("-cc", "--command-code", 
	dest="command_code", 
	default="stup1fy",
	help="Command code used by server.")
c2_options.add_argument("-rk", "--response-key", 
	dest="response_key", 
	help="Response key to use when reply to a command.")
c2_options.add_argument("-sk", "--strings-key", 
	dest="strings_key",
	default=DEFAULT_STR_XOR_KEY, 
	help="XOR key used to unobfuscate strings in implant.")		
action_options = parser.add_argument_group("Flooding Options", "Options to flood the C2 with random data")
action_options.add_argument("-d", "--decoys",
	dest="action_flood",
	type=int,
	help="Nb. of fake hosts to authentify with the C2 server")
action_options.add_argument("-b", "--beacon",
	dest="action_beacon",
	action="store_true",
	help="Sends a beacon to the specified C2 server.")
action_options.add_argument("-s", "--scan",
	dest="action_scan",
	help="File or directory to scan for Throwback implant.")
action_options.add_argument("-f", "--find",
	dest="action_search",
	nargs="+",
	help="Searches for files containing keywords in given directory.")
action_options.add_argument("-i", "--indicators",
	dest="action_ind",
	action="store_true",
	help="Extract indicators from scanned files.")

def rand_string(_minsize=4, 
	_maxsize=8, 
	_charset=string.ascii_uppercase + string.ascii_lowercase + string.digits):
	"""
	Generates a random string of variable length based on specified charset.

	@param _minsize Minimum size of the string
	@param _maxsize Maximum size of the string
	@param _charset Charset to use for generating the string
	@return A random string.
	"""
	r_size = random.randint(_minsize, _maxsize)
	r_str = ''.join(random.SystemRandom().choice(_charset) for _ in range(r_size))
	return r_str

def rand_int(_min, _max):
	"""
	Generates a random integer within the provided boundaries.
	
	@param _min Minimum boundary
	@param _max Maximum boundary
	@return A random integer
	"""
	return random.randint(_min, _max)
	
def rand_ip4addr():
	r_str = '.'.join("{:d}".format(rand_int(10, 192)) for _ in range(4))
	return r_str


def generate_host(_machineid = RANDOM_VAL, 
		_ipaddr = RANDOM_VAL,
		_hostname=DEFAULT_HOSTNAME, 
		_tbvers=DEFAULT_TB_VERS, 
		_priv=PRIV_USER):
	host = {}
	
	return host
	
def generate_random_host():
	host = {}
	host[POST_HOSTNAME] = rand_string()
	host[POST_MACHINE_ID] = rand_string(8, 16, string.ascii_uppercase + string.digits)
	host[POST_TBVERS] = DEFAULT_TB_VERS	
	host[POST_IPADDR] = rand_ip4addr()
	return host

def b64_encode(_data):
	"""
	Encodes a string into a base 64 string.
	@param _data String to encode
	@return Base64-encoded string.
	"""
	return base64.b64encode(_data)

def b64_decode(_data):
	return base64.b64decode(_data)

def rc4_crypt(key, data):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    
    return ''.join(out)

def xor_crypt(key, data):
	"""
	Xor encrypts/decrypts a string using the provided key.

	@param key Encryption/Decryption key
	@param data Plain/cipher text
	@return Cipher/plain text version of provided data.
	"""
	str = ""
	for i in range(0, len(data)):
		k = ord(key[i % len(key)])
		b = ord(data[i])
		str += chr(k ^ b)
	return str

def scan_dir(_dir, _filext=TbFileExtensions, _keywords=TbStringIndicators):
	"""
	Recursively scans a directory for 
	"""
	tb_files = []
	for root, dirs, files in os.walk(_dir, topdown=False):
		for fname in files:
			if (fname[-3:] in _filext):
				file_to_scan = os.path.join(root, fname)
				print_debug("Scanning '{:s}'...".format(file_to_scan))
				matched = scan_file(file_to_scan, _keywords)
				if (len(matched) > 0):
					print_debug("File matched 1 or more keywords: {:s}".format(file_to_scan))
					tb_files.append(file_to_scan)
		for dname in dirs:
			dir_to_scan = os.path.join(root, dname)
			tb_files_found = scan_dir(dir_to_scan, _filext, _keywords)
			tb_files += tb_files_found
	return tb_files
				

def scan_file_for_tb(_file):
	"""
	Scan the given files for indicators of the throwback implant.

	@param _file Absolute path to file to scan
	@return True if the file is suspected to be a Throwback implant, False 
		otherwise.
	"""
	is_tb = False
	found_str = scan_file(_file, TbStringIndicators)
	is_tb = (len(found_str) > 0)
	return is_tb


def scan_file(_file, _keywords):
	"""
	Searches a file for keywords. Keywords can be regular expressions.
	
	@param _file The file to scan
	@param _keywords List of keywords to search.
	@return A list of matched strings
	"""
	matched = []
	strings = extract_strings(_file)
	for str in strings:
		for k in _keywords:
			if (re.search(k, str)):
				matched.append(str)		
	return matched 
	
def extract_strings(_file, _len=6):
	"""
	Extracts strings of given length from the specified file.

	Note: this function is based on usage of the "strings" program
	in the current directory or in the PATH environment variable.

	@param _file Absolute path to the file.
	@param _len Minimum length of strings.
	@return List of strings extracted.
	"""
	str = []
	if (len(_file) > 0):
		output = subprocess.check_output(['strings', '-n', "{:d}".format(_len), _file])
		str = filter(None, output.split("\n"))
	return str

def extract_url(_fh, _fpos, _xkey):
	_fh.seek(_fpos)
	c_url = []
	b = _fh.read(4)
	while b[0] != '\xFF':
		c_url.append(b[0])
		b = _fh.read(4)
	p_url1 = xor_crypt(_xkey, c_url)
	return p_url1

def extract_bytes_with_term(_fh, _fpos, _readsize, _term):
	_fh.seek(_fpos)
	b_read = []
	b = _fh.read(_readsize)
	while (ord(b[0]) != _term):
		b_read.append(b[0])
		b = _fh.read(_readsize)
	return b_read

def extract_c2data(_file, _xkey):
	c2data = {}
	f = open(_file, 'rb')

	#
	# Read user-agent string from files
	#
	b_ua = extract_bytes_with_term(f, 168288, 2, 0)
	ua = str(bytearray(b_ua))

	#
	# Read RC4 crypto key
	#
	b_ck = extract_bytes_with_term(f, 169816, 1, 0)
	crypto_key = str(bytearray(b_ck))

	r = 0
	f.seek(170800)
	auth_code = []
	b = f.read(4)
	while r < 64:
		auth_code += b[0]
		b = f.read(4)
		r += 4
	auth_code = xor_crypt(_xkey, auth_code)

	#
	# Read service name
	#
	b_svcname = extract_bytes_with_term(f, 193680, 4, 0)
	svc_name = xor_crypt(_xkey, str(bytearray(b_svcname)))

	#
	# Read service description
	#
	b_svcdesc = extract_bytes_with_term(f, 193872, 4, 0)
	svc_desc = xor_crypt(_xkey, str(bytearray(b_svcdesc)))

	#
	# Extract URLs
	#
	urls = []
	first_url = 194384
	url_len = 60
	nb_urls = 8 
	for i in range(0, nb_urls):
		urls.append(extract_url(f, first_url+(i*url_len*4), _xkey))

	#
	# Extract command code
	#
	b_cc = extract_bytes_with_term(f, 196304, 4, 0)
	command_code = xor_crypt(_xkey, str(bytearray(b_cc)))

	c2data[HDR_UA] = ua
	c2data[POST_CRYPT_KEY] = crypto_key
	c2data[POST_CC] = command_code
	c2data[POST_AUTH_KEY] = auth_code
	c2data["svc_name"] = svc_name
	c2data["svc_desc"] = svc_desc

	for i in range(0, len(urls)):
		c2data["{:s}_{:d}".format(POST_URI, i)] = urls[i]

	f.close()
	return c2data

def send_beacon(_session, _post, _headers=[]):
	uri = _session[POST_URI].lower().strip()
	print_info("Connecting to {:s}...".format(uri))

	qs = create_querystring(_post)
	cipher_qs = rc4_crypt(_session[POST_CRYPT_KEY], qs)
	encoded_qs = b64_encode(cipher_qs)
	final_qs = encoded_qs.replace("+", "~")

	post_params = {}
	post_params = urllib.urlencode({POST_DATA : final_qs })
	
	#print_debug("{:s}={:s}".format(POST_DATA, final_qs))

	_headers["Content-type"] ="application/x-www-form-urlencoded"

	c2_connection = None;
	url = urlparse(uri)
	if (url.scheme == "https"):
		c2_connection = httplib.HTTPSConnection(url.netloc)
	else:
		c2_connection = httplib.HTTPConnection(url.netloc)
	c2_connection.request("POST", url.path, post_params, _headers)
	response = c2_connection.getresponse()

	print_info("{:d}: {:s}".format(response.status, response.reason))
	response_data = response.read()
	command = ""
	marker = ".*<hidden {:s} (.*)>.*".format(_session[POST_CC])
	match = re.search(marker, response_data)
	if (match):
		command = match.group(1).strip()
	
	return command
	
def create_querystring(_params):
	qs = ""
	for (param, value) in _params.iteritems():
		qs += "{:s}={:s}&".format(param, value)
	if (qs[-1] == "&"):
		qs = qs[:-1]
	return qs
	
def flood_c2_with_hosts(_uri, _nbhosts):
	pass

def command_desc(_command):
	cmds = {"0" : 	"No Action",
		"1" :	"Execute File",
		"2" :	"Download and Execute Program",
		"3" :	"Download",
		"4" :	"Download and Execute Library",
		"5" :	"Set Callback Time",
		"6" :	"Upgrade",
		"7" :	"Uninstall",
		"8" :	"Install Service",
		"9" :	"Execute Shellcode",
		"10":	"Short Sleep"}
	if (_command in cmds):
		return cmds[_command]
	return "Unknown"

def print_debug(_msg):
	print_msg("[>] {:s}".format(_msg))
	
def print_info(_msg):
	print_msg("[*] {:s}".format(_msg))

def print_error(_msg):
	print_msg("[-] {:s}".format(_msg))
	
def print_warning(_msg):
	print_msg("[!] {:s}".format(_msg))
	
def print_success(_msg):
	print_msg("[+] {:s}".format(_msg))
	
def print_msg(_msg):
	print(_msg)
	
def banner():
    print("Copyright (C) 2015  Jonathan Racicot <infectedpacket@gmail.com>")
    print("This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it under certain conditions.")
    print("Visit https://github.com/infectedpacket for additional software.")

def main(_args):
	try:
		c2_serv = {}
		session = {}
		headers = {}

		session[POST_URI] = _args.target_uri
		session[POST_CRYPT_KEY] = _args.crypto_key
		session[POST_CC] = _args.command_code
		session[POST_XOR] = _args.strings_key

		c2_serv[POST_AUTH_KEY] = _args.postauth_key
		if _args.response_key:
			c2_serv[POST_RESP_KEY] = _args.response_key
		
		headers[HDR_UA] = DEFAULT_UA
		headers[HDR_PRAGMA] = NO_CACHE

		#
		# Contains known Tb-related files.
		target_files = []
	
		#
		# Contains known Tb C2 servers
		target_urls = []
		if (_args.target_uri):
			target_urls.append(_args.target_uri)

		# 
		# Action: Scan file or directory
		#
		if (_args.action_scan):
			target = _args.action_scan
			#
			# Action: Recursively scan directory
			if (os.path.isdir(target)):
				target_files = scan_dir(target)
				if (len(target_files) > 0):
					print_success("Found {:d} Throwback implant(s) in '{:s}':".format(len(target_files), target))
					for f in target_files:
						print_success("\t{:s}".format(f))
				else:
					print_error("No Throwback implant located in '{:s}'.".format(target))
			#
			# Action: Scan a single file
			else:
				is_tb = scan_file_for_tb(target)
				if (is_tb):
					target_files.append(target)
					print_success("Throwback implant located in '{:s}'.".format(target))
				else:
					print_error("Failed to locate Throwback implant in '{:s}'.".format(target))

		#
		# Action: Search for files with keywords
		#
		if (_args.action_search):
			print(_args.action_search)
			location = _args.action_search[0]
			keywords = filter(None, _args.action_search[1].split(","))
			print(keywords)
			if (os.path.isdir(location)):
				files_found = scan_dir(location, _keywords=keywords)
				if (len(files_found) > 0):
					print_success("{:d} file(s) found:".format(len(files_found)))
					for f in files_found:
						print_success("\t{:s}".format(f))
				else:
					print_error("No files in '{:s}' matched any keywords provided.".format(location))
			else:
				str_found = scan_file(location, keywords)
				print_success("{:d} string(s) found:".format(len(str_found)))
				for s in str_found:
					print_success("\t{:s}".format(s))


		#
		# Action: Extract indicators from found files
		#
		if (_args.action_ind and len(target_files) > 0):
			for tb_file in target_files:
				tb_ind = extract_c2data(tb_file, session[POST_XOR])
				if (len(tb_ind) > 0):
					for (param, value) in tb_ind.iteritems():
						print_success("\t{:s}:\t{:s}".format(param, value))
				else:
					print_error("Failed to extract indicators from '{:s}'.".format(tb_file))

	
		if _args.action_beacon:
			host = generate_random_host()
			post_params = {}
			post_params.update(host)
			post_params.update(c2_serv)
			command = send_beacon(session, post_params, headers)
			if (len(command) > 0):
				command = command.replace("/", "")
				desc = command_desc(command)
				print_success("Received command '{:s}' ({:s}) from '{:s}'.".format(command, desc, session[POST_URI]))
			else:
				print_error("No command received from '{:s}'.".format(session[POST_URI]))
		elif _args.action_flood:
			target = session[POST_URI]
			nb_hosts = _args.action_flood
			print_warning("Flooding '{:s}' with {:d} hosts...".format(target, nb_hosts))
			flood_c2_with_hosts(target, nb_hosts) 
		else:
			print_error("No action specified. Terminating...")
	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		print("Line {:d}: {:s}".format(exc_tb.tb_lineno, e.message))
		traceback.print_tb(exc_tb, limit=7, file=sys.stdout)

if __name__ == "__main__":
	args = parser.parse_args()
	main(args)
