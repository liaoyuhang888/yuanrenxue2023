# coding=utf-8
import time
import execjs
from urllib.parse import urlencode
from sm3 import YRX3SM3

import requests
import httpx

# proxies = {'http://': 'http://127.0.0.1:7006', 'https://': 'http://127.0.0.1:7006'}
requests = httpx.Client(http2=True)
def encrypt(t, page):
    data = f"{t}{page}"
    print(data)
    s = YRX3SM3()
    s.sm3_update(data.encode())
    return s.sm3_final()
with open(r'.\test5.js', encoding='utf-8') as f:
    source = f.read()
ctx = execjs.compile(source, cwd=r'.\node_modules')

def get_time():
    url = 'https://match2023.yuanrenxue.cn/api/background.png'
    r = requests.get(url)
    return r.text

def main():
    url = 'https://match2023.yuanrenxue.cn/api/match2023/5'
    s = 0
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
    for page in range(1, 6):
        t = get_time()
        headers['Accept-Time'] = t
        data = {
            'page': str(page),
            'token': ctx.call('encode', str(int(t) + page)),
        }
        data = urlencode(data)
        headers['Content-Length'] = str(len(data))
        print(data)
        r = requests.post(url, data=data, headers=headers)
        print(r)
        ret = r.json()
        print(ret)
        s += sum([d['value'] for d in ret['data']])
        # time.sleep(1)
    print(s)

    

if __name__ == '__main__':
    main()