#!/usr/bin/env python3
import requests ,argparse, sys
from bs4 import BeautifulSoup
from requests.packages import urllib3
import time
import re
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
from src import logninputs, payloads, Errors
from tabulate import tabulate

# Coomon paths to fuzz for 
common_paths = [
    "admin", "login", "test", "backup", "passwords.txt", "admin.php", "admin.html", 
    "login.php", "login.html", "wp-login.php", "user", "dashboard", "cpanel", "panel", 
    "adm", "user.php", "user.html", "administrator", "db", "database", "phpmyadmin", 
    "pma", "config", "settings", "edit", "manage", "secure", "webadmin", "wp-admin", 
    "admin/login", "admin/login.php", "admin/login.html", "admin/index", "admin/index.php", 
    "admin/index.html"
]

start = time.time()

def ban():
	print(colored('''

                        \ | /
                        - * -
                         /|\ 
                        /\|/\ 
                       /  |  \ 
                      /\/\|/\/\ 
                     /    |    \ 
                    -     -     -
    __   ____  ___________ _______   _______ ____  ______ 
   / /  / __ \/ ____/ ___// ____/ | / / ___// __ \/ __ 	/
  / /  / / / / / __ \__ \/ __/ /  |/ /\__ \/ / / / /_/ /
 / /__/ /_/ / /_/ /___/ / /___/ /|  /___/ / /_/ / _, _/ 
/_____|____/\____//____/_____/_/ |_//____/\____/_/ |_|  
	''' ,"white",attrs=["bold"])+
	 colored('                    coded by @Mr_Robert',"yellow")+'\n\n'+
	colored("[-] Detecting All Login Panels : I'M a Powerful Sensor Tool, feel login panels even if it's miles away !!! " , "cyan")+'\n'
)

urllib3.disable_warnings()

parser = argparse.ArgumentParser(usage="python3 logsensor.py [-h --help] [--file ] [--url ] [--proxy] [--login] [--sqli] [--threads]", add_help=False)
parser.add_argument_group("Help")
parser.add_argument("-u", "--url", dest="url", type=str, help=" Target URL (e.g. http://example.com )")
parser.add_argument("-f", "--file", dest="file", help="Select a target hosts list file (e.g. list.txt )")
parser.add_argument("--proxy", dest="proxy", help="Proxy (e.g. http://127.0.0.1:8080)",required=False)
parser.add_argument("-l","--login", help=" run only Login panel Detector", action='store_true')
parser.add_argument("-s","--sqli", help=" run only POST Form SQLi Scanning with provided Urls" ,action='store_true')
parser.add_argument("-n","--inputname", help=" Customize actual username input for SQLi scan (default 'username' )")
parser.add_argument("-t","--threads", help=" Number of threads (default 30)" ,type=int)
parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
# Added options to Fuzz URLs before or after login panel detection checks
parser.add_argument("-fb","--fuzz-before", action='store_true', help="Fuzz URLs before other checks")
parser.add_argument("-fa","--fuzz-after", action='store_true', help="Fuzz URLs after successful login panel detection")

args = parser.parse_args()
if len(sys.argv) == 1:
		ban()
		parser.print_help()
		sys.exit()

proxies = {}
# proxies = {'http': 'http://127.0.0.1:8080' , 'https': 'http://127.0.0.1:8080'}
useragent = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36' }
inputname = "username"
threads = 30
urls=[]
loginurls = []
if args.file :
	f = open(args.file,"r").read().splitlines()
	for c in f:
		urls.append(c)

if args.url : 
	url = args.url
	urls.append(url)

if args.proxy : 
	proxies.update({'http': args.proxy ,'https': args.proxy})

if args.inputname :
	inputname = args.inputname

if args.threads :
	threads = args.threads
class main():
	def __init__(self,lines):
		self.lines = lines
		try:
			# Fuzz URLs before other checks if --fuzz-before was specified
			if args.fuzz_before:
				self.fuzz_before()

			req = requests.get(lines, headers=useragent, proxies=proxies, verify=False, timeout=8,allow_redirects=True)
			response = str(req.content)
			soup = BeautifulSoup(response, "html.parser")
			s = soup.find_all("form")[0]
			action = s.attrs.get("action")
			check = re.search("login",str(req.url))
			if action == None :
				action = ""
			if action == "?" :
				action = ""
			if action[0] == "/" :
				action = action[1:]
			if check :
				action = ""
			else:
				action = action
			if req.status_code == 200:
				for login in logninputs:
					try:
						find = re.compile(login).search(str(response))
						if find != None:
							loginurls.append(req.url +str(action))
							print(colored("[+] Login panel found ! [{}] - {}","green").format(req.url, req.status_code))
							# Fuzz URLs after successful login panel detection if --fuzz-after was specified
							if args.fuzz_after:
								fuzz_urls(req.url +str(action))
							break
						else:
							pass
					except IndexError:
						pass
		except IOError:
			pass
		except IndexError:
			pass
		except KeyboardInterrupt :
			print("\nStopped")
			exit(0)
		
def getresults():
	if loginurls :
		with open("logPanels.txt", "w") as n:
			n.write(str(loginurls).replace("[","").replace("]","").replace(",","").replace("'","").replace(" ","\n"))	
		print("=================================================================================")
		print("[+] Total Login Panels been found : " + str(len(loginurls)) + "\n\n")
	else:
		print("[+] There are no Login Panels in URLs you provided !" )


sqllen = []
sqlcontent = []
msgsql = colored("[+]","green",attrs=["bold"])+colored(" Potential SQL Injection !! in Database: ","white",attrs=["bold"])
msgurl = colored("[+] ","green",attrs=["bold"])+"injected in "+inputname +" input and url is: "
msgpyld = colored("[+]","green",attrs=["bold"])+" Payload: "
msgerr = colored("[+]","green",attrs=["bold"])+ " Detected error: "
msgreg = colored("[+]","green",attrs=["bold"])+" Regex Used: "

def inject(loginurls, inputname):
	print(colored("[@] Start POST Form SQLi Scanning [@]","cyan"))
	try:
		for ur in loginurls:

			normreq = requests.post(str(ur), headers=useragent, proxies=proxies, verify=False, timeout=8, data={inputname : "admin", "password": "badpassword"})
			normres = str(normreq.content)
			norchars = len(normres)
			print("\n"+colored("[+] URL {} Normal Request's Content Length is : {}","green").format(ur, norchars))

			#trying payloads
			for p in payloads:
				try:
					sqlreq = requests.post(str(ur), headers=useragent, proxies=proxies, verify=False, timeout=8, data={inputname : str(p) , "password": "badpassword"})
					sqlres = str(sqlreq.content)
					sqchars = len(sqlres)
					payloadId =+ 1 
					print(colored("[+] Trying Payload [ {} ] and Content Length is : {}","yellow").format(p, colored(sqchars, "white")))

					if sqchars != norchars:
						for db, errs in Errors.items():
							for err in errs:
								try:
									finderr = re.compile(err).search(str(sqlres))
									if finderr != None:
										vulnf = open('vulnPanels.txt', 'a')
										print(colored(50*"-","yellow"))
										print("Potential SQL Injection !! in Database: {}\nVulnerable Login Panel url : {}\nPayload: {}\nDetected error: {}\nRegex Used: {}\n\n".format(db,str(ur),p,finderr[0],err),file=vulnf)
										print("{}{}\n{}{}\n{}{}\n{}[ {} ]\n{}{}".format(msgsql,colored(db,"green",attrs=["bold"]),msgurl,str(ur),msgpyld,p,msgerr,colored(finderr[0],"red"),msgreg,err ))
										table = [['Vulnerable Login Panel', 'payload', 'Database', 'Detected Error(Regex Used)'], [str(ur), str(p), db, err]]
										print(colored(tabulate(table, headers='firstrow', tablefmt='grid'),"white",attrs=["bold"])+"\n\n")
										break
									else:
										pass
								except IndexError:
									pass
								except KeyboardInterrupt:
									print("\nStopped")
									exit(0)
						#break
					else:
						pass
				except IOError:
					pass
				except IndexError:
					pass
				except KeyboardInterrupt:
					print("\nStopped")
					exit(0)

	except IOError:
		pass
	except IndexError:
		pass
	except KeyboardInterrupt:
		print("\nStopped")
		exit(0)

# Added a fucntion to Fuzz the different URLS
def fuzz_urls(base_url):
    for path in common_paths:
        url = base_url + "/" + path
        response = requests.get(url)
        if response.status_code == 200:
            print("Potential hidden resource found at: " + url)


if __name__ == '__main__':
	def sensorWithThreads():
		try:
			with ThreadPoolExecutor(max_workers=threads) as executor:
				for lines in urls:
					executor.submit(main,lines)
		except KeyboardInterrupt:				
			print("\nStopped")
			exit(0)

if args.login :
	ban()
	sensorWithThreads()
	getresults()
elif args.sqli:
	ban()
	inject(urls,inputname)
else:
	ban()
	sensorWithThreads()
	getresults()
	inject(loginurls,inputname)


end = time.time()
total_time = end - start
print("\n Finished at : "+ str(total_time)+" Secs")
