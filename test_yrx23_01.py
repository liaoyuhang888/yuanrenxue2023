# coding=utf-8
import base64
import requests
import time

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from aes import YRXAES
from md5 import YRXMD5


def get_key_iv(passpharse, salt=None):
    if salt is None:
        salt = Random.new().read(8)

    salted = bytes([])
    dx = bytes([])
    state = b'\x01#Eg\x80\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10'
    while (len(salted) < 48):
        dx = YRXMD5(dx + passpharse + salt, state=state).digest()
        salted = salted + dx

    key = salted[:32]
    iv = salted[32:]
    iv = iv[:16]
    return key, iv

def ecb_encrypt(data, key, salt=None):
    aes = YRXAES(key)
    data = pad(data.encode(), 16)
    ret = aes.encrypt(data)
    if salt is not None:
        ret = b'Salted__' + salt + ret
    return base64.b64encode(ret).decode()

def ecb_encrypt2(data, key, salt=None):
    aes = AES.new(key, AES.MODE_ECB)
    data = pad(data.encode(), AES.block_size)
    print(data)
    ret = aes.encrypt(data)
    if salt is not None:
        ret = b'Salted__' + salt + ret
    return base64.b64encode(ret).decode()

def translate(ret: str):
    raw_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    new_table = 'abcdefghijklmnopqrstuvwxyzABCDEDGHIJKLMNOPQRSTUVWXYZ0123456789+/='
    table_dict = str.maketrans(raw_table, new_table)
    ret = ret.translate(table_dict)
    return ret

def test():
    RCON = [0, 1, 2, 4, 128, 27, 54, 8, 16, 32, 64]
    r = 0xbb76994f
    salt = b'\xbbv\x99O\xbbv\x99O'
    key, iv = get_key_iv(b'666yuanrenxue66', salt)
    print(key)
    ret = ecb_encrypt('16854358299401', key, salt)
    ret = translate(ret)
    state = b'\x01#Eg\x80\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10'
    ret = YRXMD5(ret, state=state).hexdigest()
    print(ret)

def encrypt(t, page):
    salt = b'\xbbv\x99O\xbbv\x99O'
    key, iv = get_key_iv(b'666yuanrenxue66', salt)
    ret = ecb_encrypt(f'{t}{page}', key, salt)
    ret = translate(ret)
    state = b'\x01#Eg\x80\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10'
    ret = YRXMD5(ret, state=state).hexdigest()
    return ret



def main():
    url = 'https://match2023.yuanrenxue.cn/api/match2023/1'
    s = 0
    for page in range(1, 6):
        t = int(time.time() * 1000)
        data = {
            'page': str(page),
            'token': encrypt(t, page),
            'now': t
        }
        r = requests.post(url, data=data)
        ret = r.json()
        print(ret)
        s += sum([d['value'] for d in ret['data']])
    print(s)

    

if __name__ == '__main__':
    main()