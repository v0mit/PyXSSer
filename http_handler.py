'''
Created on 17. aug. 2011

@author: v0mit
'''
import urllib, urllib2

class _http_handler():
    def __init__(self, proxy=None):
        
        if proxy:
            self.install_proxy(proxy)
        
        else:
            self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
            
        self.user_agent = 'http_handler.v1.1 v0mit@darkpy.net'
        urllib2.install_opener(self.opener)

    def request(self, url, data=None):
        req = urllib2.Request(url)
        req.add_header('User-Agent', self.user_agent)
        
        if data != None:
            data = urllib.urlencode(data)
            try:
                response = self.opener.open(req,data)
            except urllib2.URLError as errno:              
                raise HTTPError("[!]urllib2.URLError({0})\n[URL:{1}][Data:{2}".format(errno, url, data))
                
            return response.read()
        else:
            try:
                response = self.opener.open(req)
            except urllib2.URLError as errno:
                raise HTTPError("[!]urllib2.URLError({0})\n[URL:{1}]".format(errno, url))
                
            except ValueError as errno:
                raise HTTPError("[!]ValueError({0}\n".format(errno))
            
            return response.read()
    
    def install_proxy(self, proxy): 
        if len(proxy) is not 2:
            raise HTTPError("Invalid proxy.")
            return
            
        if proxy[0] == "SOCK":
            import socket
            
            try:
                import socks
            except ImportError:
                raise HTTPError("SocksiPy not installed, http://socksipy.sourceforge.net/")
                return
            
            try:        
                ip, port = proxy[1].split(":")
            except ValueError as errno:
                raise HTTPError("{0} Invalid proxy(IP:PORT)".format(errno))
        
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, ip, int(port))
            socket.socket = socks.socksocket
            
            self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
            
        else:          
            http_proxy= {"http":"http://{0}/".format(proxy[1])}
            proxy_support = urllib2.ProxyHandler(http_proxy)
            self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(), proxy_support)
        
class HTTPError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)