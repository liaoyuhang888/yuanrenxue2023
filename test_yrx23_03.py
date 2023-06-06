# coding=utf-8
from collections import OrderedDict

from sm3 import YRX3SM3

import requests

def encrypt(t, page):
    data = f"{t}{page}"
    print(data)
    s = YRX3SM3()
    s.sm3_update(data.encode())
    return s.sm3_final()

def get_time():
    url = 'https://match2023.yuanrenxue.cn/api/background.png'
    r = requests.get(url)
    return r.text


def main():
    url = 'https://match2023.yuanrenxue.cn/api/match2023/3'
    s = 0
    headers = OrderedDict({
        'Accept':'application/json, text/javascript, */*; q=0.01', 
        'Accept-Encoding': 'gzip, deflate, br', 
        'Accept-Language':"zh-CN,zh;q=0.9", 
        'Accept-Time': '', 
        'Cache-Control': 'no-cache',
        'Content-Length':'77',
        'Referer': 'https://match2023.yuanrenxue.cn/topic/3',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest'
        })
    for page in range(1, 6):
        t = get_time()
        headers['Accept-Time'] = t
        data = {
            'page': str(page),
            'token': encrypt(t, page),
        }
        # print(headers)
        r = requests.post(url, data=data, headers=headers)
        print(r)
        ret = r.json()
        # print(ret)
        s += sum([d['value'] for d in ret['data']])
        # time.sleep(1)
    print(s)

    

if __name__ == '__main__':
    main()