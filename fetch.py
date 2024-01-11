#!/usr/bin/env python3
import yaml
import json
import base64
from urllib.parse import quote, unquote, urlparse
import requests
import datetime
import traceback
import binascii
import threading
import sys
import os
from types import FunctionType as function
from typing import Set, List, Dict, Union, Any, Optional

try: PROXY = open("local_proxy.conf").read().strip()
except FileNotFoundError: LOCAL = False; PROXY = None
else:
    if not PROXY: PROXY = None
    LOCAL = not PROXY

def b64encodes(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def b64encodes_safe(s):
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8')

def b64decodes(s):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

def b64decodes_safe(s):
    ss = s + '=' * ((4-len(s)%4)%4)
    try:
        return base64.urlsafe_b64decode(ss.encode('utf-8')).decode('utf-8')
    except UnicodeDecodeError: raise
    except binascii.Error: raise

DEFAULT_UUID = '8'*8+'-8888'*3+'-'+'8'*12

CLASH2VMESS = {'name': 'ps', 'server': 'add', 'port': 'port', 'uuid': 'id', 
              'alterId': 'aid', 'cipher': 'scy', 'network': 'net', 'servername': 'sni'}
VMESS2CLASH = {}
for k,v in CLASH2VMESS.items(): VMESS2CLASH[v] = k

VMESS_EXAMPLE = {
    "v": "2", "ps": "", "add": "0.0.0.0", "port": "0", "aid": "0", "scy": "auto",
    "net": "tcp", "type": "none", "tls": "", "id": DEFAULT_UUID
}

CLASH_CIPHER_VMESS = "auto aes-128-gcm chacha20-poly1305 none".split()
CLASH_CIPHER_SS = "aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb \
        aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 chacha20-ietf \
        xchacha20 chacha20-ietf-poly1305 xchacha20-ietf-poly1305".split()
CLASH_SSR_OBFS = "plain http_simple http_post random_head tls1.2_ticket_auth tls1.2_ticket_fastauth".split()
CLASH_SSR_PROTOCOL = "origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b".split()

ABFURLS = (
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/ChineseFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_15_DnsFilter/filter.txt",
    # "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-ag.txt",
    # "https://raw.githubusercontent.com/banbendalao/ADgk/master/ADgk.txt",
    # "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt",
    # "https://anti-ad.net/adguard.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock",
    # "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt",
    # "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    # "https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_lite.txt",
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
    # "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/domain.txt",
)

FAKE_IPS = "8.8.8.8; 8.8.4.4; 1.1.1.1; 1.0.0.1; 4.2.2.2; 4.2.2.1; 114.114.114.114; 127.0.0.1".split('; ')
FAKE_DOMAINS = ".google.com .github.com".split()

FETCH_TIMEOUT = (6, 5)

BANNED_WORDS = b64decodes('5rOV6L2uIOi9ruWtkCDova4g57uDIOawlCDlip8=').split()

# !!! JUST FOR DEBUGING !!!
DEBUG_NO_NODES = os.path.exists("local_NO_NODES")
DEBUG_NO_ADBLOCK = os.path.exists("local_NO_ADBLOCK")

class UnsupportedType(Exception): pass
class NotANode(Exception): pass

session = requests.Session()
session.trust_env = False
if PROXY: session.proxies = {'http': PROXY, 'https': PROXY}
session.headers["User-Agent"] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.58'

exc_queue: List[str] = []

class Node:
    names: Set[str] = set()
    DATA_TYPE = Dict[str, Any]

    def __init__(self, data: Union[DATA_TYPE, str]) -> None:
        if isinstance(data, dict):
            self.data: __class__.DATA_TYPE = data
            self.type = data['type']
        elif isinstance(data, str):
            self.load_url(data)
        else: raise TypeError
        if not self.data['name']:
            self.data['name'] = "未命名"
        if 'password' in self.data:
            self.data['password'] = str(self.data['password'])
        self.data['type'] = self.type
        self.name: str = self.data['name']

    def __str__(self):
        return self.url

    def __hash__(self):
        data = self.data
        try:
            path = ""
            if self.type == 'vmess':
                path = data['network']+':'
                if data['network'] == 'ws':
                    if 'ws-opts' in data:
                        try:
                            path += data['ws-opts']['headers']['Host']
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            path += '/'+data['ws-opts']['path']
                elif data['network'] == 'h2':
                    if 'h2-opts' in data:
                        if 'host' in data['h2-opts']:
                            path += ','.join(data['h2-opts']['host'])
                        if 'path' in data['h2-opts']:
                            path += '/'+data['h2-opts']['path']
                elif data['network'] == 'grpc':
                    if 'grpc-opts' in data:
                        if 'grpc-service-name' in data['grpc-opts']:
                            path += data['grpc-opts']['grpc-service-name']
            elif self.type == 'ss':
                if 'plugin-opts' in data:
                    opts = data['plugin-opts']
                    if 'host' in opts:
                        path = opts['host']
                    if 'path' in opts:
                        path += '/'+opts['path']
            elif self.type == 'ssr':
                if 'obfs-param' in data:
                    path = data['obfs-param']
            elif self.type == 'trojan':
                if 'sni' in data:
                    path = data['sni']+':'
                if data['network'] == 'ws':
                    if 'ws-opts' in data:
                        try:
                            path += data['ws-opts']['headers']['Host']
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            path += '/'+data['ws-opts']['path']
            hashstr = f"{self.type}:{data['server']}:{data['port']}:{path}"
            return hash(hashstr)
        except Exception: return hash('__ERROR__')
    
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return hash(self) == hash(other)
        else:
            return False

    def load_url(self, url: str) -> None:
        try: self.type, dt = url.split("://")
        except ValueError: raise NotANode(url)
        # === Fix begin ===
        if not self.type.isascii():
            self.type = ''.join([_ for _ in self.type if _.isascii()])
            url = self.type+'://'+url.split("://")[1]
        # === Fix end ===
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            try: v.update(json.loads(b64decodes(dt)))
            except Exception:
                raise UnsupportedType('vmess', 'SP')
            self.data = {}
            for key, val in v.items():
                if key in VMESS2CLASH:
                    self.data[VMESS2CLASH[key]] = val
            self.data['tls'] = (v['tls'] == 'tls')
            self.data['alterId'] = int(self.data['alterId'])
            if v['net'] == 'ws':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['headers'] = {'Host': v['host']}
                self.data['ws-opts'] = opts
            elif v['net'] == 'h2':
                opts = {}
                if 'path' in v:
                    opts['path'] = v['path']
                if 'host' in v:
                    opts['host'] = v['host'].split(',')
                self.data['h2-opts'] = opts
            elif v['net'] == 'grpc' and 'path' in v:
                self.data['grpc-opts'] = {'grpc-service-name': v['path']}

        elif self.type == 'ss':
            info = url.split('@')
            srvname = info.pop()
            if '#' in srvname:
                srv, name = srvname.split('#')
            else:
                srv = srvname
                name = ''
            server, port = srv.split(':')
            try:
                port = int(port)
            except ValueError:
                raise UnsupportedType('ss', 'SP')
            info = '@'.join(info)
            if not ':' in info:
                info = b64decodes_safe(info)
            if ':' in info:
                cipher, passwd = info.split(':')
            else:
                cipher = info
                passwd = ''
            self.data = {'name': unquote(name), 'server': server, 
                    'port': port, 'type': 'ss', 'password': passwd, 'cipher': cipher}

        elif self.type == 'ssr':
            if '?' in url:
                parts = dt.split(':')
            else:
                parts = b64decodes_safe(dt).split(':')
            try:
                passwd, info = parts[-1].split('/?')
            except: raise
            passwd = b64decodes_safe(passwd)
            self.data = {'type': 'ssr', 'server': parts[0], 'port': parts[1],
                    'protocol': parts[2], 'cipher': parts[3], 'obfs': parts[4],
                    'password': passwd, 'name': ''}
            for kv in info.split('&'):
                k_v = kv.split('=')
                if len(k_v) != 2:
                    k = k_v[0]
                    v = ''
                else: k,v = k_v
                if k == 'remarks':
                    self.data['name'] = v
                elif k == 'group':
                    self.data['group'] = v
                elif k == 'obfsparam':
                    self.data['obfs-param'] = v
                elif k == 'protoparam':
                    self.data['protocol-param'] = v

        elif self.type == 'trojan':
            parsed = urlparse(url)
            self.data = {'name': unquote(parsed.fragment), 'server': parsed.hostname, 
                    'port': parsed.port, 'type': 'trojan', 'password': unquote(parsed.username)} # type: ignore
            if parsed.query:
                for kv in parsed.query.split('&'):
                    k,v = kv.split('=')
                    if k == 'allowInsecure':
                        self.data['skip-cert-verify'] = (v != 0)
                    elif k == 'sni': self.data['sni'] = v
                    elif k == 'alpn':
                        if '%2C' in v:
                            self.data['alpn'] = ["h2", "http/1.1"]
                        else:
                            self.data['alpn'] = [v]
                    elif k == 'type':
                        self.data['network'] = v
                    elif k == 'serviceName':
                        if 'grpc-opts' not in self.data:
                            self.data['grpc-opts'] = {}
                        self.data['grpc-opts']['grpc-service-name'] = v
                    elif k == 'host':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        if 'headers' not in self.data['ws-opts']:
                            self.data['ws-opts']['headers'] = {}
                        self.data['ws-opts']['headers']['Host'] = v
                    elif k == 'path':
                        if 'ws-opts' not in self.data:
                            self.data['ws-opts'] = {}
                        self.data['ws-opts']['path'] = v
        
        else: raise UnsupportedType(self.type)

    def format_name(self, max_len=30) -> None:
        self.data['name'] = self.name
        for word in BANNED_WORDS:
            self.data['name'] = self.data['name'].replace(word, '*'*len(word))
        if len(self.data['name']) > max_len:
            self.data['name'] = self.data['name'][:max_len]+'...'
        if self.data['name'] in Node.names:
            i = 0
            new: str = self.data['name']
            while new in Node.names:
                i += 1
                new = f"{self.data['name']} #{i}"
            self.data['name'] = new
        
    @property
    def isfake(self) -> bool:
        if 'server' not in self.data: return True
        if '.' not in self.data['server']: return True
        if self.data['server'] in FAKE_IPS: return True
        for domain in FAKE_DOMAINS:
            if self.data['server'] == domain.lstrip('.'): return True
            if self.data['server'].endswith(domain): return True
        # TODO: Fake UUID
        if self.type == 'vmess' and len(self.data['uuid']) != len(DEFAULT_UUID):
            return True
        return False

    @property
    def url(self) -> str:
        data = self.data
        if self.type == 'vmess':
            v = VMESS_EXAMPLE.copy()
            for key,val in data.items():
                if key in CLASH2VMESS:
                    v[CLASH2VMESS[key]] = val
            if v['net'] == 'ws':
                if 'ws-opts' in data:
                    try:
                        v['host'] = data['ws-opts']['headers']['Host']
                    except KeyError: pass
                    if 'path' in data['ws-opts']:
                        v['path'] = data['ws-opts']['path']
            elif v['net'] == 'h2':
                if 'h2-opts' in data:
                    if 'host' in data['h2-opts']:
                        v['host'] = ','.join(data['h2-opts']['host'])
                    if 'path' in data['h2-opts']:
                        v['path'] = data['h2-opts']['path']
            elif v['net'] == 'grpc':
                if 'grpc-opts' in data:
                    if 'grpc-service-name' in data['grpc-opts']:
                        v['path'] = data['grpc-opts']['grpc-service-name']
            if ('tls' in data) and data['tls']:
                v['tls'] = 'tls'
            return 'vmess://'+b64encodes(json.dumps(v, ensure_ascii=False))

        if self.type == 'ss':
            passwd = b64encodes_safe(data['cipher']+':'+data['password'])
            return f"ss://{passwd}@{data['server']}:{data['port']}#{quote(data['name'])}"
        if self.type == 'ssr':
            ret = (':'.join([str(self.data[_]) for _ in ('server','port',
                                        'protocol','cipher','obfs')]) +
                    b64encodes_safe(self.data['password']) +
                    f"remarks={b64encodes_safe(self.data['name'])}")
            for k, urlk in (('obfs-param','obfsparam'), ('protocol-param','protoparam'), ('group','group')):
                if k in self.data:
                    ret += '&'+urlk+'='+b64encodes_safe(self.data[k])
            return "ssr://"+ret

        if self.type == 'trojan':
            passwd = quote(data['password'])
            name = quote(data['name'])
            ret = f"trojan://{passwd}@{data['server']}:{data['port']}?"
            if 'skip-cert-verify' in data:
                ret += f"allowInsecure={int(data['skip-cert-verify'])}&"
            if 'sni' in data:
                ret += f"sni={data['sni']}&"
            if 'alpn' in data:
                if len(data['alpn']) >= 2:
                    ret += "alpn=h2%2Chttp%2F1.1&"
                else:
                    ret += f"alpn={quote(data['alpn'][0])}&"
            if 'network' in data:
                if data['network'] == 'grpc':
                    ret += f"type=grpc&serviceName={data['grpc-opts']['grpc-service-name']}"
                elif data['network'] == 'ws':
                    ret += f"type=ws&"
                    if 'ws-opts' in data:
                        try:
                            ret += f"host={data['ws-opts']['headers']['Host']}&"
                        except KeyError: pass
                        if 'path' in data['ws-opts']:
                            ret += f"path={data['ws-opts']['path']}"
            ret = ret.rstrip('&')+'#'+name
            return ret

        raise UnsupportedType(self.type)

    @property
    def clash_data(self) -> DATA_TYPE:
        ret = self.data.copy()
        if 'password' in ret and ret['password'].isdigit():
            ret['password'] = '!!str '+ret['password']
        if 'uuid' in ret and len(ret['uuid']) != len(DEFAULT_UUID):
            ret['uuid'] = DEFAULT_UUID
        if 'group' in ret: del ret['group']
        if 'cipher' in ret and not ret['cipher']:
            ret['cipher'] = 'auto'
        return ret

    def supports_clash(self) -> bool:
        if self.isfake: return False
        if 'network' in self.data and self.data['network'] in ('h2','grpc'):
            # A quick fix for #2
            self.data['tls'] = True
        if self.type == 'vless': return False
        if self.data['type'] == 'vless': return False
        if 'cipher' not in self.data: return True
        if not self.data['cipher']: return True
        elif self.type == 'vmess':
            supported = CLASH_CIPHER_VMESS
        elif self.type == 'ss' or self.type == 'ssr':
            supported = CLASH_CIPHER_SS
        elif self.type == 'trojan': return True
        else: supported = []
        if self.data['cipher'] not in supported: return False
        if self.type == 'ssr':
            if 'obfs' in self.data and self.data['obfs'] not in CLASH_SSR_OBFS:
                return False
            if 'protocol' in self.data and self.data['protocol'] not in CLASH_SSR_PROTOCOL:
                return False
        if 'plugin-opts' in self.data and 'mode' in self.data['plugin-opts'] \
                and not self.data['plugin-opts']['mode']: return False
        return True

    def supports_ray(self) -> bool:
        if self.isfake: return False
        # if self.type == 'ss':
        #     if 'plugin' in self.data and self.data['plugin']: return False
        # elif self.type == 'ssr':
        #     return False
        return True

class Source():
    def __init__(self, url: Union[str, function]) -> None:
        if isinstance(url, function):
            self.url: str = "dynamic://"+url.__name__
            self.url_source: function = url
        elif url.startswith('+'):
            self.url_source: str = url
            self.date = datetime.datetime.now()# + datetime.timedelta(days=1)
            self.gen_url()
        else:
            self.url: str = url
            self.url_source: None = None
        self.content: Union[str, List[str], int] = None
        self.sub: list = None

    def gen_url(self) -> None:
        self.url_source: str
        tags = self.url_source.split()
        url = tags.pop()
        while tags:
            tag = tags.pop(0)
            if tag[0] != '+': break
            if tag == '+date':
                url = self.date.strftime(url)
                self.date -= datetime.timedelta(days=1)
        self.url = url

    def get(self, depth=2) -> None:
        global exc_queue
        if self.content: return
        try:
            if self.url.startswith("dynamic:"):
                content: Union[str, List[str]] = self.url_source()
            else:
                global session
                content: str = ""
                with session.get(self.url, stream=True) as r:
                    if r.status_code != 200:
                        if depth > 0 and isinstance(self.url_source, str):
                            exc = f"'{self.url}' 抓取时 {r.status_code}"
                            self.gen_url()
                            exc += "，重新生成链接：\n\t"+self.url
                            exc_queue.append(exc)
                            self.get(depth-1)
                        else:
                            self.content = r.status_code
                        return
                    tp = None
                    pending = None
                    early_stop = False
                    for chunk in r.iter_content():
                        if early_stop: pending = None; break
                        chunk: bytes
                        if pending is not None:
                            chunk = pending + chunk
                            pending = None
                        if tp == 'sub':
                            content += chunk.decode(errors='ignore')
                            continue
                        lines: List[bytes] = chunk.splitlines()
                        if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                            pending = lines.pop()
                        while lines:
                            line = lines.pop(0).rstrip().decode(errors='ignore').replace('\\r','')
                            if not line: continue
                            if not tp:
                                if ': ' in line:
                                    kv = line.split(': ')
                                    if len(kv) == 2 and kv[0].isalpha():
                                        tp = 'yaml'
                                elif line[0] == '#': pass
                                else: tp = 'sub'
                            if tp == 'yaml':
                                if content:
                                    if line in ("proxy-groups:", "rules:", "script:"):
                                        early_stop=True; break
                                    content += line+'\n'
                                elif line == "proxies:":
                                    content = line+'\n'
                            elif tp == 'sub':
                                content = chunk.decode(errors='ignore')
                    if pending is not None: content += pending.decode(errors='ignore')
        except KeyboardInterrupt: raise
        except requests.exceptions.RequestException:
            self.content = -1
        except:
            self.content = -2
            exc = "在抓取 '"+self.url+"' 时发生错误：\n"+traceback.format_exc()
            exc_queue.append(exc)
        else:
            self.content: Union[str, List[str]] = content
            self.parse()

    def parse(self) -> None:
        global exc_queue
        try:
            text = self.content
            if isinstance(text, str):
                if "proxies:" in text:
                    # Clash config
                    config = yaml.full_load(text.replace("!<str>","!!str"))
                    sub: List[str] = config['proxies']
                elif '://' in text:
                    # V2Ray raw list
                    sub = text.strip().splitlines()
                else:
                    # V2Ray Sub
                    sub = b64decodes(text.strip()).strip().splitlines()
            else: sub = text # 动态节点抓取后直接传入列表
            self.sub = sub
        except KeyboardInterrupt: raise
        except: exc_queue.append(
                "在解析 '"+self.url+"' 时发生错误：\n"+traceback.format_exc())

class DomainTree:
    def __init__(self) -> None:
        self.children: Dict[str, __class__] = {}
        self.here: bool = False

    def insert(self, domain: str) -> None:
        segs = domain.split('.')
        segs.reverse()
        self._insert(segs)

    def _insert(self, segs: List[str]) -> None:
        if not segs:
            self.here = True
            return
        if self.here: return
        if segs[0] not in self.children:
            self.children[segs[0]] = __class__()
        child = self.children[segs[0]]
        del segs[0]
        child._insert(segs)

    def get(self) -> List[str]:
        ret: List[str] = []
        for name, child in self.children.items():
            if child.here: ret.append(name)
            else: ret.extend([_+'.'+name for _ in child.get()])
        return ret

def extract(url: str) -> Union[Set[str], int]:
    global session
    res = session.get(url)
    if res.status_code != 200: return res.status_code
    urls = set()
    for line in res.text:
        if line.startswith("http"):
            urls.add(line)
    return urls

merged: Dict[str, Node] = {}
unknown: Set[str] = set()
used: Dict[int, Dict[int, str]] = {}
def merge(source_obj: Source, sourceId=-1) -> None:
    global merged, unknown
    sub = source_obj.sub
    if not sub: print("空订阅，跳过！", end='', flush=True); return
    for p in sub:
        if isinstance(p, str):
            if not p.isascii() or '://' not in p: continue
            ok = True
            for ch in '!|@#`~()[]{} ':
                if ch in p:
                    ok = False; break
            if not ok: continue
        try: n = Node(p)
        except KeyboardInterrupt: raise
        except UnsupportedType as e:
            if len(e.args) == 1:
                print(f"不支持的类型：{e}")
            unknown.add(p)
        except: traceback.print_exc()
        else:
            n.format_name()
            Node.names.add(n.data['name'])
            if hash(n) not in merged:
                merged[hash(n)] = n
            else:
                merged[hash(n)].data.update(n.data)
            if hash(n) not in used:
                used[hash(n)] = {}
            used[hash(n)][sourceId] = n.name

def raw2fastly(url: str) -> str:
    # 由于 Fastly CDN 不好用，因此换成 ghproxy.net，见 README。
    # 2023/06/27: ghproxy.com 比 ghproxy.net 稳定性更好，为避免日后代码失效，进行修改
    # 2023/06/28: ghproxy.com 似乎有速率或并发限制，改回原来的镜像
    # 2023/10/01: ghproxy.net tcping 有大量丢包，且之前出现过证书未续期的问题，改掉
    # 2023/12/23: 全都废了
    if not LOCAL: return url
    if url.startswith("https://raw.githubusercontent.com/"):
        url = url[34:].split('/')
        url[1] += '@'+url[2]
        del url[2]
        url = "https://fastly.jsdelivr.net/gh/"+('/'.join(url))
        return url
    #     return "https://ghproxy.com/"+url
    return url

def merge_adblock(adblock_name: str, rules: Dict[str, str]) -> None:
    print("正在解析 Adblock 列表... ", end='', flush=True)
    blocked: Set[str] = set()
    for url in ABFURLS:
        url = raw2fastly(url)
        try:
            res = session.get(url)
        except requests.exceptions.RequestException as e:
            try:
                print(f"{url} 下载失败：{e.args[0].reason}")
            except Exception:
                print(f"{url} 下载失败：无法解析的错误！")
                traceback.print_exc()
            continue
        if res.status_code != 200:
            print(url, res.status_code)
            continue
        for line in res.text.strip().splitlines():
            line = line.strip()
            if line[:2] == '||' and ('/' not in line) and ('?' not in line) and \
                            (line[-1] == '^' or line.endswith("$all")):
                blocked.add(line.strip('al').strip('|^$'))

    domain_root = DomainTree()
    domain_keys = set()
    for domain in blocked:
        if '/' in domain: continue
        if '*' in domain:
            domain = domain.strip('*')
            if '*' not in domain:
                domain_keys.add(domain)
            continue
        segs = domain.split('.')
        if len(segs) == 4 and domain.replace('.','').isdigit(): # IP
            for seg in segs: # '223.73.212.020' is not valid
                if not seg: break
                if seg[0] == '0' and seg != '0': break
            else:
                rules[f'IP-CIDR,{domain}/32'] = adblock_name
        else:
            domain_root.insert(domain)

    for domain in domain_keys:
        rules[f'DOMAIN-KEYWORD,{domain}'] = adblock_name

    for domain in domain_root.get():
        for key in domain_keys:
            if key in domain: break
        else: rules[f'DOMAIN-SUFFIX,{domain}'] = adblock_name

    print(f"共有 {len(rules)} 条规则")

def main():
    global exc_queue, FETCH_TIMEOUT, ABFURLS, AUTOURLS, AUTOFETCH
    sources = open("sources.list", encoding="utf-8").read().strip().splitlines()
    if DEBUG_NO_NODES:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已启用无节点调试，程序产生的配置不能被直接使用 !!!")
        AUTOURLS = AUTOFETCH = sources = []
    print("正在生成动态链接...")
    for auto_fun in AUTOURLS:
        print("正在生成 '"+auto_fun.__name__+"'... ", end='', flush=True)
        try: url = auto_fun()
        except requests.exceptions.RequestException: print("失败！")
        except: print("错误：");traceback.print_exc()
        else:
            if url:
                if isinstance(url, str):
                    sources.append(url)
                elif isinstance(url, (list, tuple, set)):
                    sources.extend(url)
                print("成功！")
            else: print("跳过！")
    print("正在整理链接...")
    sources_final = set()
    airports = set()
    for source in sources:
        if not source: continue
        if source[0] == '#': continue
        sub = source
        if sub[0] == '!':
            if LOCAL: continue
            sub = sub[1:]
        if sub[0] == '*':
            isairport = True
            sub = sub[1:]
        else: isairport = False
        if sub[0] == '+':
            tags = sub.split()
            sub = tags.pop()
            sub = ' '.join(tags) + ' ' +raw2fastly(sub)
        else:
            sub = raw2fastly(sub)
        if isairport: airports.add(sub)
        else: sources_final.add(sub)

    if airports:
        print("正在抓取机场列表...")
        for sub in airports:
            print("合并 '"+sub+"'... ", end='', flush=True)
            try:
                res = extract(sub)
            except KeyboardInterrupt:
                print("正在退出...")
                break
            except requests.exceptions.RequestException:
                print("合并失败！")
            except: traceback.print_exc()
            else:
                if isinstance(res, int):
                    print(res)
                else:
                    for url in res:
                        sources_final.add(url)
                    print("完成！")

    print("正在整理链接...")
    sources_final = list(sources_final)
    sources_final.sort()
    sources_obj = [Source(url) for url in (sources_final + AUTOFETCH)]

    print("开始抓取！")
    threads = [threading.Thread(target=_.get, daemon=True) for _ in sources_obj]
    for thread in threads: thread.start()
    for i in range(len(sources_obj)):
        try:
            for t in range(1, FETCH_TIMEOUT[0]+1):
                print("抓取 '"+sources_obj[i].url+"'... ", end='', flush=True)
                try: threads[i].join(timeout=FETCH_TIMEOUT[1])
                except KeyboardInterrupt:
                    print("正在退出...")
                    FETCH_TIMEOUT = (1, 0)
                    break
                if not threads[i].is_alive(): break
                print(f"{5*t}s")
            if threads[i].is_alive():
                print("超时！")
                continue
            res = sources_obj[i].content
            if isinstance(res, int):
                if res < 0: print("抓取失败！")
                else: print(res)
            else:
                print("正在合并... ", end='', flush=True)
                try:
                    merge(sources_obj[i], sourceId=i)
                except KeyboardInterrupt:
                    print("正在退出...")
                    break
                except:
                    print("失败！")
                    traceback.print_exc()
                else: print("完成！")
        except KeyboardInterrupt:
            print("正在退出...")
            break
        while exc_queue:
            print(exc_queue.pop(0), file=sys.stderr, flush=True)

    print("\n正在写出 V2Ray 订阅...")
    txt = ""
    unsupports = 0
    for hashp, p in merged.items():
        try:
            if hashp in used:
                # 注意：这一步也会影响到下方的 Clash 订阅，不用再执行一遍！
                p.data['name'] = ','.join([str(_) for _ in sorted(list(used[hash(p)]))])+'|'+p.data['name']
            if p.supports_ray():
                txt += p.url + '\n'
            else: unsupports += 1
        except: traceback.print_exc()
    for p in unknown:
        txt += p+'\n'
    print(f"共有 {len(merged)-unsupports} 个正常节点，{len(unknown)} 个无法解析的节点，共",
            len(merged)+len(unknown),f"个。{unsupports} 个节点不被 V2Ray 支持。")

    with open("list_raw.txt",'w') as f:
        f.write(txt)
    with open("list.txt",'w') as f:
        f.write(b64encodes(txt))
    print("写出完成！")

    with open("config.yml", encoding="utf-8") as f:
        conf: Dict[str, Any] = yaml.full_load(f)
    
    rules: Dict[str, str] = {}
    if DEBUG_NO_ADBLOCK:
        # !!! JUST FOR DEBUGING !!!
        print("!!! 警告：您已关闭对 Adblock 规则的抓取 !!!")
    else:
        merge_adblock(conf['proxy-groups'][-2]['name'], rules)

    snip_conf: Dict[str, Dict[str, Any]] = {}
    ctg_nodes: Dict[str, List[Node.DATA_TYPE]] = {}
    categories: Dict[str, List[str]] = {}
    try:
        with open("snippets/_config.yml", encoding="utf-8") as f:
            snip_conf = yaml.full_load(f)
    except (OSError, yaml.error.YAMLError):
        print("片段配置读取失败：")
        traceback.print_exc()
    else:
        print("正在按地区分类节点...")
        categories = snip_conf['categories']
        for ctg in categories: ctg_nodes[ctg] = []
        for node in merged.values():
            if node.supports_clash():
                ctgs = []
                for ctg, keys in categories.items():
                    for key in keys:
                        if key in node.name:
                            ctgs.append(ctg)
                            break
                    if ctgs and keys[-1] == 'OVERALL':
                        break
                if len(ctgs) == 1:
                    ctg_nodes[ctgs[0]].append(node.clash_data)
        for ctg, proxies in ctg_nodes.items():
            with open("snippets/nodes_"+ctg+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'proxies': proxies}, f, allow_unicode=True)

    # print("正在抓取 Google IP 列表... ", end='', flush=True)
    # proxy_name: str = conf['proxy-groups'][0]['name']
    # try:
    #     prefixes: List[Dict[str,str]] = session.get("https://www.gstatic.com/ipranges/goog.json").json()['prefixes']
    #     for prefix in prefixes:
    #         for tp, ip in prefix.items():
    #             if tp.startswith('ipv4'):
    #                 rules['IP-CIDR,'+ip] = proxy_name
    #             elif tp.startswith('ipv6'):
    #                 rules['IP-CIDR6,'+ip] = proxy_name
    # except requests.exceptions.RequestException:
    #     print("抓取失败！")
    # except Exception:
    #     print("解析失败！")
    #     traceback.print_exc()
    # else: print("解析成功！")

    print("正在写出 Clash 订阅...")
    match_rule = None
    for rule in conf['rules']:
        tmp = rule.strip().split(',')
        if len(tmp) == 2 and tmp[0] == 'MATCH':
            match_rule = rule
            break
        if len(tmp) == 3:
            rtype, rargument, rpolicy = tmp
        elif len(tmp) == 4:
            rtype, rargument, rpolicy, rresolve = tmp
            rpolicy += ','+rresolve
        else: print("规则 '"+rule+"' 无法被解析！"); continue
        k = rtype+','+rargument
        if k not in rules:
            rules[k] = rpolicy
    conf['rules'] = [','.join(_) for _ in rules.items()]+[match_rule]
    conf['proxies'] = []
    ctg_base: Dict[str, Any] = conf['proxy-groups'][3].copy()
    names_clash: Union[Set[str], List[str]] = set()
    for p in merged.values():
        if p.supports_clash():
            conf['proxies'].append(p.clash_data)
            names_clash.add(p.data['name'])
    names_clash = list(names_clash)
    for group in conf['proxy-groups']:
        if not group['proxies']:
            group['proxies'] = names_clash
    if snip_conf:
        conf['proxy-groups'][-1]['proxies'] = []
        ctg_selects: List[str] = conf['proxy-groups'][-1]['proxies']
        ctg_disp: Dict[str, str] = snip_conf['categories_disp']
        for ctg, payload in ctg_nodes.items():
            if ctg in ctg_disp:
                disp = ctg_base.copy()
                disp['name'] = ctg_disp[ctg]
                if not payload: disp['proxies'] = ['REJECT']
                else: disp['proxies'] = [_['name'] for _ in payload]
                conf['proxy-groups'].append(disp)
                ctg_selects.append(disp['name'])
    with open("list.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump(conf, allow_unicode=True).replace('!!str ',''))
    with open("snippets/nodes.yml", 'w', encoding="utf-8") as f:
        f.write(yaml.dump({'proxies': conf['proxies']}, allow_unicode=True).replace('!!str ',''))

    if snip_conf:
        print("正在写出配置片段...")
        name_map: Dict[str, str] = snip_conf['name-map']
        snippets: Dict[str, List[str]] = {}
        for rpolicy in name_map.values(): snippets[rpolicy] = []
        for rule, rpolicy in rules.items():
            if ',' in rpolicy: rpolicy = rpolicy.split(',')[0]
            if rpolicy in name_map:
                snippets[name_map[rpolicy]].append(rule)
        for name, payload in snippets.items():
            with open("snippets/"+name+".yml", 'w', encoding="utf-8") as f:
                yaml.dump({'payload': payload}, f, allow_unicode=True)

    print("正在写出统计信息...")
    out = "序号,链接,节点数\n"
    for i, source in enumerate(sources_obj):
        out += f"{i},{source.url},"
        try: out += f"{len(source.sub)}"
        except: out += '0'
        out += '\n'
    out += f"\n总计,,{len(merged)}\n"
    open("list_result.csv",'w').write(out)

    print("写出完成！")

if __name__ == '__main__':
    from dynamic import AUTOURLS, AUTOFETCH
    main()
