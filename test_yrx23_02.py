# coding=utf-8
import requests
import time

from md5 import YRX2MD5

def encrypt(t, page):
    state = b"\x93\xae\xa7\x88\xb3Oy'~\xfe\x90\r\xc6\xc3[J"
    data = f"{t}/api/match2023/2?page={page}"
    print(data)
    m = YRX2MD5(data, state=state, count=0)
    return m.hexdigest()


def main():
    base_url = 'https://match2023.yuanrenxue.cn/api/match2023/2'
    s = 0
    for page in range(1, 6):
        t = int(time.time() * 1000)
        url = f"{base_url}?page={page}&token={encrypt(t, page) + str(t)}"
        print(url)
        r = requests.post(url)
        ret = r.json()
        print(ret)
        s += sum([d['value'] for d in ret['data']])
    print(s)

    

if __name__ == '__main__':
    main()