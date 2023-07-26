# coding=utf-8
import ctypes

#-------以下函数也可用于其它算法中---------
def rotation_left(x, num):
    # 循环左移
    num %= 32
    left = (x << num) % (2 ** 32)
    right = (x >> (32 - num)) % (2 ** 32)
    result = left ^ right
    return result

def Int2Bin(x, k):
    x = str(bin(x)[2:])
    result = "0" * (k - len(x)) + x
    return result

def right_without_sign(num, bit=0) -> int:
    # example: 
    #   javascript: -1 >>> 1 === python: right_without_sign(-1, 1)
    MAX32INT = 0xffffffff
    val = ctypes.c_uint32(num).value >> bit
    return (val + (MAX32INT + 1)) % (2 * (MAX32INT + 1)) - MAX32INT - 1



#-------以上函数也可用于其余算法中-----------

class SM3:

    def __init__(self):
        # 常量初始化
        self.IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
        self.T = [0x79cc4519, 0x7a879d8a]
        self.maxu32 = 2 ** 32
        self.w1 = [0] * 68
        self.w2 = [0] * 64

    def ff(self, x, y, z, j):
        # 布尔函数FF
        result = 0
        if j < 16:
            result = x ^ y ^ z
        elif j >= 16:
            result = (x & y) | (x & z) | (y & z)
        return result

    def gg(self, x, y, z, j):
        # 布尔函数GG
        result = 0
        if j < 16:
            result = x ^ y ^ z
        elif j >= 16:
            result = (x & y) | (~x & z)
        return result

    def p(self, x, mode):
        result = 0
        # 置换函数P
        # 输入参数X的长度为32bit(=1个字)
        # 输入参数mode共两种取值：0和1
        if mode == 0:
            result = x ^ rotation_left(x, 9) ^ rotation_left(x, 17)
        elif mode == 1:
            result = x ^ rotation_left(x, 15) ^ rotation_left(x, 23)
        return result

    def sm3_fill(self, msg):
        # 填充消息，使其长度为512bit的整数倍
        # 输入参数msg为bytearray类型
        # 中间参数msg_new_bin为二进制string类型
        # 输出参数msg_new_bytes为bytearray类型
        length = len(msg)   # msg的长度（单位：byte）
        l = length * 8      # msg的长度（单位：bit）

        num = length // 64
        remain_byte = length % 64
        msg_remain_bin = ""
        msg_new_bytes = bytearray((num + 1) * 64)  ##填充后的消息长度，单位：byte

        # 将原数据存储至msg_new_bytes中
        for i in range(length):
            msg_new_bytes[i] = msg[i]

        # remain部分以二进制字符串形式存储
        remain_bit = remain_byte * 8     #单位：bit
        for i in range(remain_byte):
            msg_remain_bin += "{:08b}".format(msg[num * 64 + i])

        k = (448 - l - 1) % 512
        while k < 0:
            # k为满足 l + k + 1 = 448 % 512 的最小非负整数
            k += 512

        msg_remain_bin += "1" + "0" * k + Int2Bin(l, 64)

        for i in range(0, 64 - remain_byte):
            str = msg_remain_bin[i * 8 + remain_bit: (i + 1) * 8 + remain_bit]
            temp = length + i
            msg_new_bytes[temp] = int(str, 2) #将2进制字符串按byte为组转换为整数
        return msg_new_bytes

    def sm3_msg_extend(self, msg):
        # 扩展函数: 将512bit的数据msg扩展为132个字（w1共68个字，w2共64个字）
        # 输入参数msg为bytearray类型,长度为512bit=64byte
        for i in range(0, 16):
            self.w1[i] = int.from_bytes(msg[i * 4:(i + 1) * 4], byteorder="big")

        for i in range(16, 68):
            self.w1[i] = self.p(self.w1[i-16] ^ self.w1[i-9] ^ rotation_left(self.w1[i-3], 15), 1) ^ rotation_left(self.w1[i-13], 7) ^ self.w1[i-6]

        for i in range(64):
            self.w2[i] = self.w1[i] ^ self.w1[i+4]

        # 测试扩展数据w1和w2
        # print("w1:")
        # for i in range(0, len(self.w1), 8):
        #     print(hex(self.w1[i]))
        # print("w2:")
        # for i in range(0, len(self.w2), 8):
        #     print(hex(self.w2[i]))

    def sm3_compress(self,msg):
        # 压缩函数
        # 输入参数v为初始化参数，类型为bytes/bytearray，大小为256bit
        # 输入参数msg为512bit的待压缩数据

        self.sm3_msg_extend(msg)
        ss1 = 0

        A = self.IV[0]
        B = self.IV[1]
        C = self.IV[2]
        D = self.IV[3]
        E = self.IV[4]
        F = self.IV[5]
        G = self.IV[6]
        H = self.IV[7]

        for j in range(64):
            if j < 16:
                ss1 = rotation_left((rotation_left(A, 12) + E + rotation_left(self.T[0], j)) % self.maxu32, 7)
            elif j >= 16:
                ss1 = rotation_left((rotation_left(A, 12) + E + rotation_left(self.T[1], j)) % self.maxu32, 7)
            ss2 = ss1 ^ rotation_left(A, 12)
            tt1 = (self.ff(A, B, C, j) + D + ss2 + self.w2[j]) % self.maxu32
            tt2 = (self.gg(E, F, G, j) + H + ss1 + self.w1[j]) % self.maxu32
            D = C
            C = rotation_left(B, 9)
            B = A
            A = tt1
            H = G
            G = rotation_left(F, 19)
            F = E
            E = self.p(tt2, 0)

            # 测试IV的压缩中间值
            # print("j= %d：" % j, hex(A)[2:], hex(B)[2:], hex(C)[2:], hex(D)[2:], hex(E)[2:], hex(F)[2:], hex(G)[2:], hex(H)[2:])

        self.IV[0] ^= A
        self.IV[1] ^= B
        self.IV[2] ^= C
        self.IV[3] ^= D
        self.IV[4] ^= E
        self.IV[5] ^= F
        self.IV[6] ^= G
        self.IV[7] ^= H

    def sm3_update(self, msg):
        # 迭代函数
        # 输入参数msg为bytearray类型
        # msg_new为bytearray类型
        msg_new = self.sm3_fill(msg)   # msg_new经过填充后一定是512的整数倍
        n = len(msg_new) // 64         # n是整数，n>=1

        for i in range(0, n):
            self.sm3_compress(msg_new[i * 64:(i + 1) * 64])

    def sm3_final(self):
        digest_str = ""
        for i in range(len(self.IV)):
            digest_str += f'{self.IV[i]:08x}'

        return digest_str.lower()

    def hashFile(self, filename):
        with open(filename,'rb') as fp:
            contents = fp.read()
            self.sm3_update(bytearray(contents))
        return self.sm3_final()


class YRX3SM3(SM3):
    def __init__(self):
        self.IV = [0x7380067c, 0x7634d2c9, 0x170042d6, 0xda887534, 0xa10c30bc, 0x151137ad, 0xe37caa4d, 0xeeeb0f4e]
        self.T = [0x79dd4519, 0x7c179d8a]
        self.maxu32 = 0xfcffffff
        self.w1 = [0] * 68
        self.w2 = [0] * 64
    
    def sm3_fill(self, msg):
        # 填充消息，使其长度为512bit的整数倍
        # 输入参数msg为bytearray类型
        # 中间参数msg_new_bin为二进制string类型
        # 输出参数msg_new_bytes为bytearray类型
        length = len(msg)   # msg的长度（单位：byte）
        l = length * 8      # msg的长度（单位：bit）

        num = length // 64
        remain_byte = length % 64
        msg_remain_bin = ""
        msg_new_bytes = bytearray((num + 1) * 64)  ##填充后的消息长度，单位：byte

        # 将原数据存储至msg_new_bytes中
        re = []
        for i in range(length):
            ch = msg[i]
            st = []
            st.append(ch &  0xFE)
            ch = ch >> 8
            while ch:
                st.append(ch &  0xFE)
                ch = ch >> 8
            st.reverse()
            re.extend( st );
        for i in range(len(re)):
            msg_new_bytes[i] = re[i]

        # remain部分以二进制字符串形式存储
        remain_bit = remain_byte * 8     #单位：bit
        for i in range(remain_byte):
            msg_remain_bin += "{:08b}".format(msg[num * 64 + i])

        k = (448 - l - 1) % 512
        while k < 0:
            # k为满足 l + k + 1 = 448 % 512 的最小非负整数
            k += 512

        msg_remain_bin += "1" + "0" * k + Int2Bin(l, 64)

        for i in range(0, 64 - remain_byte):
            str = msg_remain_bin[i * 8 + remain_bit: (i + 1) * 8 + remain_bit]
            temp = length + i
            msg_new_bytes[temp] = int(str, 2) #将2进制字符串按byte为组转换为整数
        return msg_new_bytes

    def sm3_compress(self,msg):
        # 压缩函数
        # 输入参数v为初始化参数，类型为bytes/bytearray，大小为256bit
        # 输入参数msg为512bit的待压缩数据

        self.sm3_msg_extend(msg)
        ss1 = 0

        A = self.IV[0]
        B = self.IV[1]
        C = self.IV[2]
        D = self.IV[3]
        E = self.IV[4]
        F = self.IV[5]
        G = self.IV[6]
        H = self.IV[7]

        for j in range(64):
            if j < 16:
                ss1 = rotation_left(A, 12) + E + rotation_left(self.T[0], j)
            elif j >= 16:
                ss1 = rotation_left(A, 12) + E + rotation_left(self.T[1], j)
            ss1 = ss1 & self.maxu32
            ss1 = rotation_left(right_without_sign(ss1, 0), 7)
            ss2 = ss1 ^ rotation_left(A, 12)
            tt1 = self.ff(A, B, C, j) + D + ss2 + self.w2[j]
            tt1 = right_without_sign(tt1 & 0xfffffffa, 0)
            tt2 = self.gg(E, F, G, j) + H + ss1 + self.w1[j]
            tt2 = right_without_sign(tt2 & 0xffafffff, 0)
            D = C
            C = rotation_left(B, 9)
            B = A
            A = tt1
            H = G
            G = rotation_left(F, 19)
            F = E
            E = self.p(tt2, 0)

            # 测试IV的压缩中间值
            # print("j= %d：" % j, hex(A)[2:], hex(B)[2:], hex(C)[2:], hex(D)[2:], hex(E)[2:], hex(F)[2:], hex(G)[2:], hex(H)[2:])

        self.IV[0] ^= A
        self.IV[1] ^= B
        self.IV[2] ^= C
        self.IV[3] ^= D
        self.IV[4] ^= E
        self.IV[5] ^= F
        self.IV[6] ^= G
        self.IV[7] ^= H


class YRX6SM3(SM3):
    def __init__(self):
        self.IV = [0x7322266f, 0x2224b2b9, 0x172005d7, 0xd2210600, 0xaaaa30bc, 0x1aaaa8aa, 0xedddee4d, 0xb0ee0e4e]
        self.T = [2027754777, 2054647178]
        self.maxu32 = 2 ** 32
        self.w1 = [0] * 68
        self.w2 = [0] * 64


if __name__ == "__main__":

    # msg1 = bytearray(b"abc")
    # print("msg1:", msg1.hex(), len(msg1))

    # test1 = SM3()
    # test1.sm3_update(msg1)
    # digest1 = test1.sm3_final()
    # print("digest1:", digest1)
    
    # msg2 = bytearray(b'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd')
    # msg2 = bytes(msg2)
    # print("msg2:", msg2.hex(), len(msg2))

    # test2 = SM3()
    # test2.sm3_update(msg2)
    # digest2 = test2.sm3_final()
    # print("digest2:", digest2)

    # 求大小为48M的文件的摘要，大约需要7分钟
    # test3 = SM3()
    # file_digest = test3.hashFile("test.exe")
    # print('file_digest', file_digest)

    # s = YRX3SM3()
    # s.sm3_update('16859546283933'.encode())
    # print(s.sm3_final())
    s = YRX6SM3()
    s.sm3_update('a51edb86b414c4a8885fe4e8f4082aeb'.encode())
    print(s.sm3_final())
    s = YRX6SM3()
    s.sm3_update('7cfebf9469c055386b776cccbec9e25e'.encode())
    print(s.sm3_final())
    

