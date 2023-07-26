# coding=utf-8
import time
import execjs

# import requests
import httpx

proxies = {'http://': 'http://127.0.0.1:7006', 'https://': 'http://127.0.0.1:7006'}
requests = httpx.Client(http2=True, proxies=proxies, verify=False)

with open(r'.\test4.js', encoding='utf-8') as f:
    source = f.read()
ctx = execjs.compile(source, cwd=r'.\node_modules')

def main():
    url = 'https://match2023.yuanrenxue.cn/api/match2023/4'
    s = 0
    headers = {
            'Connection': 'keep-alive',
            'Content-Length': '130',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'https://match2023.yuanrenxue.cn/topic/4',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Referer': 'https://match2023.yuanrenxue.cn/topic/4',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
    }
    requests.headers = default_headers
    requests.get('https://match2023.yuanrenxue.cn/topic/4') # 设置cookie
    for page in range(1, 6):
        r = requests.get('https://match2023.yuanrenxue.cn/api/background.png')
        print(r.text)
        data = {
            'page': str(page),
            # 'yt4': r.json()['data'],
            'yt4': ctx.call('encode', r.text), # 随便什么加密也能过
        }
        from urllib.parse import urlencode
        data = urlencode(data)
        print(data)
        headers['Content-Length'] = str(len(data))
        print(headers)
        r = requests.post(url, data=data, headers=headers)
        print(r)
        ret = r.json()
        print(ret)
        s += sum([d['value'] for d in ret['data']])
        # time.sleep(1)
    print(s)

    

if __name__ == '__main__':
    main()