# coding=utf-8
import time
from urllib.parse import urlencode
from sm3 import YRX6SM3
from md5 import YRX6MD5

import requests
import httpx


requests = httpx.Client(http2=True)
def encrypt(data, state):
    # state = b'\xaf"Eg\x19\x88\xcf\xef\xf6pIgzH\xd7\xef'
    m = YRX6MD5(str(data).encode(), state)
    ret = m.hexdigest()
    s = YRX6SM3()
    s.sm3_update(ret.encode())
    ret = s.sm3_final()

    m = YRX6MD5(str(data + 1).encode(), state)
    ret1 = m.hexdigest()
    s = YRX6SM3()
    s.sm3_update(ret1.encode())
    ret1 = s.sm3_final()
    ret += ret1
    ret = int(ret[data % 100], 16)
    return data + ret

def get_time():
    url = 'https://match2023.yuanrenxue.cn/api/background.png'
    r = requests.get(url)
    return r.text

def main():
    url = 'https://match2023.yuanrenxue.cn/api/match2023/6'
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
        }
        data = urlencode(data)
        headers['Content-Length'] = str(len(data))
        print(data)
        r = requests.post(url, data=data, headers=headers)
        print(r)
        ret = r.json()
        print(ret)
        
        for i, d in enumerate(ret['data']):
            if i == 3:
                state = b'@"Eg!]\xcf\xef\x8a\x9bIg\x8a\xab\xcd\xef'
            elif i == 9:
                state = b'0\x02/g\x01/\x1d\xf0J\xa8\x9bfJ\x84u\xf0'
            else:
                state = b'\xaf"Eg\x19\x88\xcf\xef\xf6pIgzH\xd7\xef'
            r = encrypt(d['value'], state)
            print(r)
            s += r
        print
        # time.sleep(1)
    print(s)

    

if __name__ == '__main__':
    main()