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
import redis

#logger
import log
logger=log.setlog("backtester.py")

#global variable
userMap={}
#redis-server
r = redis.Redis(host='localhost',port=6379,db=0)


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
		logger.info('try to login. username={0},password={1}'.format(username,pwd))
		url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.4)'
		try:
			servertime, nonce, pubkey, rsakv = self.get_servertime(username)
			#print servertime
			#print nonce
			#print pubkey
			#print rsakv
		except:
			logger.critical( 'get servertime error!')
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
		if match is None:
		    return 0
		login_url = match.group(1)
		urllib2.urlopen(login_url)
		return 1

def findFollowTab(html,srcuid):
    followTab_reg = re.compile('<script>FM.view\(\{\"ns\":\"pl.content.followTab.index"(.*)\}\)</script>')
    followTab_match = followTab_reg.search(html)
    if followTab_match is None:
        logger.warning('Cannot find followTab. uid = {0}'.format(srcuid))
        return
    followTab = followTab_match.group()
    return followTab

def calScore(singleUser):
    reg = re.compile(r'uid=(\d+)&fnick=(.*?)&sex=.*current=fans\\" >(\d+)')
    rst_match = reg.search(singleUser)
    rst = rst_match.groups()
    uid,fnick,fans=rst[0],rst[1],int(rst[2])
    if fans<5000:
        return uid,fnick,0

    score = 1
    if '微博个人认证' and '股' in singleUser:
        score = score + 5
    if '微博签约自媒体' and '股' in singleUser:
        score = score + 5
    #if '股' in singleUser:
    #    score = score + fans/1000
    return uid,fnick,score


def getHisSimilar(srcuid):
    response = urllib2.urlopen('http://weibo.com/p/100505' + srcuid + '/follow?relate=fans_follow')
    html = response.read()
    followTab = findFollowTab(html,srcuid)
    if followTab is None:
        return
    singleUser_reg = re.compile('<li><a href=\\\\\\"javascript:;\\\\\" action-type=\\\\\"webim.conversation\\\\\"(.*?)display:none;')
    singleUser = singleUser_reg.findall(followTab)
    for user in singleUser:
        uid,fnick,score = calScore(user)
        if score ==0:
            continue
        logger.info('uid={0} fnick={1} score={2}'.format(uid,fnick,score))
        if r.zscore('candidate',uid) != -1:
            userMap[uid] = fnick
            r.zincrby('candidate',uid,score)


if __name__ == '__main__':
    N = 1000
    #login
    filename = './config/account'#保存微博账号的用户名和密码，第一行为用户名，第二行为密码
    WBLogin = weiboLogin()
    if WBLogin.login(filename)==1:
        logger.info('Login success!')
    else:
        logger.critical('Login error!')
        exit()

    #result file
    f = open("result.txt",'w')
    
    #init
    r.delete('candidate')
    r.zadd('candidate','1282871591',100,'1896820725',100,'1645823934',100,'2436093373',100,'1613005690',100)
    userMap['1896820725']=u'天津股侠'.encode('utf8')
    userMap['1282871591']=u'花荣'.encode('utf8')
    userMap['1645823934']=u'李大霄'.encode('utf8')
    userMap['2436093373']=u'金融侠女盈盈'.encode('utf8')
    userMap['1613005690']=u'雨农谈股'.encode('utf8')

    #search
    for i in range(N):
        if r.zcard('candidate')>0:
            print r.zrange('candidate',0,10,desc=True,withscores=True)
            next = r.zrange('candidate',0,0,desc=True)[0]
            logger.info('Iter {0}: uid = {1}'.format(i,next))
            getHisSimilar(next)
            r.zadd('candidate',next,-1)
            r.rpush('result',next)
            f.write(next + ' ' +userMap[next] + '\n')

    #candidate results
    f.write('\n')
    for uid in r.zrange('candidate',0,-1,desc=True):
        if r.zscore('candidate',uid) != -1:
            f.write(uid + ' ' +userMap[uid] + '\n')
            
    f.close()