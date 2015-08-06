#! /usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
import urllib2
import cookielib
import base64
import re
import json
import rsa
import binascii

#global variable
userMap={}
candidateSet = set()


class weiboLogin:
	cj = cookielib.LWPCookieJar()
	cookie_support = urllib2.HTTPCookieProcessor(cj)
	opener = urllib2.build_opener(cookie_support, urllib2.HTTPHandler)
	urllib2.install_opener(opener)
	postdata = {
		'entry': 'weibo',
		'gateway': '1',
		'from': '',
		'savestate': '7',
		'userticket': '1',
		'ssosimplelogin': '1',
		'vsnf': '1',
		'vsnval': '',
		'su': '',
		'service': 'miniblog',
		'servertime': '',
		'nonce': '',
		'pwencode': 'rsa2',
		'sp': '',
		'encoding': 'UTF-8',
		'prelt': '115',
		'rsakv': '',
		'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
		'returntype': 'META'
	}

	def get_servertime(self,username):
		url = 'http://login.sina.com.cn/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su=%s&rsakt=mod&client=ssologin.js(v1.4.4)' % username
		data = urllib2.urlopen(url).read()
		p = re.compile('\((.*)\)')
		try:
			json_data = p.search(data).group(1)
			data = json.loads(json_data)
			servertime = str(data['servertime'])
			nonce = data['nonce']
			pubkey = data['pubkey']
			rsakv = data['rsakv']
			return servertime, nonce, pubkey, rsakv
		except:
			print 'Get severtime error!'
			return None

	def get_pwd(self, password, servertime, nonce, pubkey):
		rsaPublickey = int(pubkey, 16)
		key = rsa.PublicKey(rsaPublickey, 65537) #创建公钥
		message = str(servertime) + '\t' + str(nonce) + '\n' + str(password) #拼接明文js加密文件中得到
		passwd = rsa.encrypt(message, key) #加密
		passwd = binascii.b2a_hex(passwd) #将加密信息转换为16进制。
		return passwd

	def get_user(self, username):
		username_ = urllib.quote(username)
		username = base64.encodestring(username_)[:-1]
		return username
	def get_account(self,filename):
		f=file(filename)
		flag = 0
		for line in f:
			if flag == 0:
				username = line.strip()
				flag +=1
			else:
				pwd = line.strip()
		f.close()
		return username,pwd
	def login(self,filename):
		username,pwd = self.get_account(filename)

		url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.4)'
		try:
			servertime, nonce, pubkey, rsakv = self.get_servertime(username)
			#print servertime
			#print nonce
			#print pubkey
			#print rsakv
		except:
			print 'get servertime error!'
			return
		weiboLogin.postdata['servertime'] = servertime
		weiboLogin.postdata['nonce'] = nonce
		weiboLogin.postdata['rsakv'] = rsakv
		weiboLogin.postdata['su'] = self.get_user(username)
		weiboLogin.postdata['sp'] = self.get_pwd(pwd, servertime, nonce, pubkey)
		weiboLogin.postdata = urllib.urlencode(weiboLogin.postdata)
		headers = {'User-Agent':'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0 Chrome/20.0.1132.57 Safari/536.11'}
		req  = urllib2.Request(
			url = url,
			data = weiboLogin.postdata,
			headers = headers
		)
		result = urllib2.urlopen(req)
		text = result.read()
		#print text
		p = re.compile('location\.replace\(\'(.*)\'\)')
		match = re.search(p,text)
		login_url = match.group(1)
		print login_url
		urllib2.urlopen(login_url)
		return 1

def getHisSimilar(srcuid):
    print srcuid
    response = urllib2.urlopen('http://weibo.com/p/100505' + srcuid + '/follow?relate=fans_follow')
    html = response.read()
    followTab_reg = re.compile('<script>FM.view\(\{\"ns\":\"pl.content.followTab.index"(.*)\}\)</script>')
    followTab_match = followTab_reg.search(html)
    if followTab_match is None:
        return
    followTab = followTab_match.group()
    similiar_reg = re.compile(ur'uid=(\d+)&fnick=([\u4e00-\u9fa5]+)&sex=')
    rst = re.findall(similiar_reg, followTab.decode('utf8'))
    for (uid,fnick) in rst:
        userMap[uid] = fnick
        candidateSet.add(uid)

if __name__ == '__main__':
    filename = './config/account'#保存微博账号的用户名和密码，第一行为用户名，第二行为密码
    WBLogin = weiboLogin()
    if WBLogin.login(filename)==1:
        print 'Login success!'
    else:
        print 'Login error!'
	exit()

    candidateSet.add('1282871591')
    for i in range(5):
        if len(candidateSet)>0:
            getHisSimilar(candidateSet.pop())

    for uid in userMap:
        print userMap[uid]