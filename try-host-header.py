#This script automates attempts to forge host headers
#Specify a target server and a file name
#The file should contain hostnames, one on each line, to put in the host header
#Requests are routed through a local proxy for inspection

import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def try_host(pool, target, host):
    print(host)
    rsp = pool.request("GET", f"https://{target}/", headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36"
    })

def try_all(target, fname):
    pool = urllib3.ProxyManager("http://localhost:8080", cert_reqs='CERT_NONE')
    with open(fname, "r") as f:
        for line in f:
            host = line.strip()
            if host != "":
                try_host(pool, target, host)

def main():
    try_all(sys.argv[1], sys.argv[2])

main()