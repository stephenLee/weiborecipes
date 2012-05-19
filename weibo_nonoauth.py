#!/usr/bin/env python
#-*- coding: utf-8 -*-

import urllib2
import urllib, gzip, StringIO, cookielib

import time,re, base64, hashlib, ast, codecs

from urllib2 import Request, urlopen, URLError, HTTPError
from BeautifulSoup import BeautifulSoup
# HTTP code 401 Unauthorized
# HTTP code 404 Not found

def get_info():
	# weibo username and password
    username = ''
    password = ''
    # preprocess username
    username = username.replace('@', '%40')
    name = base64.b64encode(username)
    print name
    # First step: GET prelogin to get servertime pcid and nonce
    pre_url = 'http://login.sina.com.cn/sso/prelogin.php?entry=miniblog&callback=sinaSSOController.preloginCallBack&su=%s&client=ssologin.js(v1.3.19)&_=%s' % (name, str(time.time()).replace('.', '4'))
    pre_req = urllib2.Request(url=pre_url)
    pre_response = urllib2.urlopen(pre_req)
    pre_message = pre_response.read()
    print pre_message
    server_data = re.findall("{.*}", pre_message)[0]
    print server_data

    # string to dict
    server_data = ast.literal_eval(server_data)
    servertime = server_data['servertime']
    pcid = server_data['pcid']
    nonce = server_data['nonce']
    print servertime, pcid, nonce
    # encypt the passward, algorithm: hex_sha1("" + hex_sha1(hex_sha1(pass))+servertime+nonce)
    pass1 = hashlib.sha1(password)
    pass2 = hashlib.sha1(pass1.hexdigest())
    sp = hashlib.sha1(pass2.hexdigest() + str(servertime) + str(nonce)).hexdigest()
    print sp

    pinfo = {
        'client':'ssologin.js(v1.3.19)', 'entry': 'weibo', 'gateway':'1', 'from':'','savestate':'0', 'useticket':'1',
        'ssosimplelogin':'1','vsnf':'1', 'vsnval':'','su': name, 'service':'miniblog','servertime':servertime, 'nonce': nonce,
        'pwencode':'wsse', 'sp': sp, 'encoding': 'UTF-8', 'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
        'returntype':'META'}

    # post header
    headers = {
        'Host': 'login.sina.com.cn', 'User-Agent': 'Mozilla/5.0 (X11; Linux i686; rv:11.0) Gecko/20100101 Firefox/11.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-language': 'en-us,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate', 'Connection': 'keep-alive', 'Referer': 'http://weibo.com/', 
        'Content-Type': 'application/x-www-form-urlencoded'}

    # Second step: POST login
    login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.3.19)'
    data = urllib.urlencode(pinfo)
    print data
    request = urllib2.Request(login_url, data, headers)
    response = urllib2.urlopen(request)
#########################################################################################################################################################
   # set_cookie = response.headers.getheader("Set-Cookie")
#    set_cookie = ast.literal_eval(set_cookie)
    #print set_cookie
    page = response.read()
    # Third step: GET
 #   kandian_url = 'http://kandian.com/logon/do_crossdomain.php?action=login&savestate=%s&callback=sinaSSOController.doCrossDomainCallBack&scriptId=ssoscript0&client=ssologin.js(v1.3.19)&_=%s' % (set_cookie['savestate'], str(time.time()).replace('.', '4'))
  #  urllib2.urlopen(urllib2.Request(kandian_url))
    # Forth step: GET
   # fourth_url = 'http://login.t.cn/sinaurl/sso.json?action=login&uid=%s&callback=sinaSSOController.doCrossDomainCallBack&scriptId=ssoscript1&client=ssologin.js(v1.3.19)&_%s' % (set_cookie['uid'], str(time.time()).replace('.', '4'))
    #urllib2.urlopen(urllib2.Request(fourth_url))
    # Fifth step: GET
    #fifth_url = 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack&ssosavestate=%s&ticket=%s&retcode=0' % (set_cookie['ssosavestate'], set_cookie['ticket'])
    #urllib2.urlopen(urllib2.Request(fifth_url))

############################################################################################################################################################

    data = StringIO.StringIO(page)
    gzipper = gzip.GzipFile(fileobj=data)
    html = gzipper.read()
    print html
    
    # get new url, match all url, and get second
    new_url = re.findall('location.replace.*=0', html)[0]
    new_url = re.findall('http.*0', new_url)[0]
    print new_url
    
    cookies = cookielib.CookieJar()
    cookies.extract_cookies(response, request)
    
    cookie_handler = urllib2.HTTPCookieProcessor(cookies)
    redirect_handler = urllib2.HTTPRedirectHandler()
    opener = urllib2.build_opener(redirect_handler, cookie_handler)
    opener.open(new_url)
    
    my_page = opener.open('http://weibo.com/stephenlee10')
    print my_page.headers.getheader('Content-Type') # urf-8
    content = my_page.read()
    
    ucontent = unicode(content, 'utf-8')
    
    f = codecs.open('./home.html', 'w', 'utf-8')
    f.write(ucontent)
    f.close()
    print ucontent.encode("utf-8")
#    soup = BeautifulSoup(content, fromEncoding='utf-8')
 #   print soup.originalEncoding
    #print soup.prettify()
  #  print soup.head.parent.name
    
# Display Chinese character   
def transcoding(page):
    data = StringIO.StringIO(page)
    gzipper = gzip.GzipFile(fileobj=data)
    result = gzipper.read()
    print result
    
##############################################################

def main():
    print ("Starting.")
    get_info()
    print ("Ending.")

if __name__ == '__main__':
    main()
