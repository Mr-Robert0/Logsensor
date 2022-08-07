# Logsensor
A Powerful Sensor Tool to discover login panels, and POST Form SQLi Scanning 

**Features**  
- login panel Scanning for multiple hosts
- Proxy compatibility (http, https)
- Login panel scanning are done in multiprocessing 
> so the script is super fast at scanning many urls


> quick tutorial & screenshots are shown at the bottom  
> project contribution tips at the bottom  

---

**Installation** 
```
git clone https://github.com/Mr-Robert0/Logsensor.git
cd Logsensor && sudo chmod +x logsensor.py install.sh
pip install -r requirements.txt
./install.sh

```

> Dependencies  
> - [re](https://pypi.org/project/regex/)  
> - [bs4](https://pypi.python.org/pypi/bs4)  
> - [termcolor](https://pypi.python.org/pypi/termcolor)  
> - [argparse](https://pypi.python.org/pypi/argparse)
> - [tabulate](https://pypi.python.org/pypi/tabulate/)
> - [requests](https://pypi.python.org/pypi/requests/)

---
### Quick Tutorial  
**1. Multiple hosts scanning to detect login panels**  
- You can increase the threads (default 30)
- only run login detector module
```python
python3 logsensor.py -f <subdomains-list> 
python3 logsensor.py -f <subdomains-list> -t 50
python3 logsensor.py -f <subdomains-list>  --login
```
**2. Targeted SQLi form scanning**  
- can provide only specifc url of login panel with --sqli or -s flag for run only SQLi form scanning Module
- turn on the proxy to see the requests
- customize user input name of login panel with actual name (default "username")
```python
python logsensor.py -u www.example.com/login --sqli 
python logsensor.py -u www.example.com/login -s --proxy http://127.0.0.1:8080
python logsensor.py -u www.example.com/login -s --inputname email
```

**View help**  
```python
python logsensor.py --help

usage: logsensor.py [-h --help] [--file ] [--url ] [--proxy] [--login] [--sqli] [--threads]

optional arguments:
  -u , --url           Target URL (e.g. http://example.com/ )
  -f , --file          Select a target hosts list file (e.g. list.txt )
  --proxy              Proxy (e.g. http://127.0.0.1:8080)
  -l, --login          run only Login panel Detector Module
  -s, --sqli           run only POST Form SQLi Scanning Module with provided Login panels Urls 
  -n , --inputname     Customize actual username input for SQLi scan (e.g. 'username' or 'email')
  -t , --threads       Number of threads (default 30)
  -h, --help           Show this help message and exit

```
---
### Screenshots
![1](https://raw.githubusercontent.com/Mr-Robert0/Logsensor/main/Screenshots/1.png)
![2](https://raw.githubusercontent.com/Mr-Robert0/Logsensor/main/Screenshots/2.png)

---

### Development
**TODO**  
1. adding "POST form SQli (Time based) scanning" and check for delay 
2. Fuzzing on Url Paths So as not to miss any login panel
