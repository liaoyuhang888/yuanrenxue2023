import struct
import ctypes

S11 = 7
S12 = 12
S13 = 17
S14 = 22
S21 = 5
S22 = 9
S23 = 14
S24 = 20
S31 = 4
S32 = 11
S33 = 16
S34 = 23
S41 = 6
S42 = 10
S43 = 15
S44 = 21

PADDING = b"\x80" + 63*b"\0"

# F, G, H and I: basic MD5 functions.
def F(x, y, z): return (((x) & (y)) | ((~x) & (z)))

def G(x, y, z): return (((x) & (z)) | ((y) & (~z)))

def H(x, y, z): return ((x) ^ (y) ^ (z))

def I(x, y, z): return((y) ^ ((x) | (~z)))

def ROTATE_LEFT(x, n):
    x = x & 0xffffffff   # make shift unsigned
    return (((x) << (n)) | ((x) >> (32-(n)))) & 0xffffffff

# FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
# Rotation is separate from addition to prevent recomputation.

def FF(a, b, c, d, x, s, ac):
    a = a + F ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a

def GG(a, b, c, d, x, s, ac):
    a = a + G ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a

def HH(a, b, c, d, x, s, ac):
    a = a + H ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a

def II(a, b, c, d, x, s, ac):
    a = a + I ((b), (c), (d)) + (x) + (ac)
    a = ROTATE_LEFT ((a), (s))
    a = a + b
    return a # must assign this to a


class md5(object):
    digest_size = 16  # size of the resulting hash in bytes
    block_size  = 64  # hash algorithm's internal block size
    S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
    M = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
         0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
         0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
         0x6b901122,0xfd987193,0xa679438e,0x49b40821,
         0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
         0xd62f105d,0x2441453,0xd8a1e681,0xe7d3fbc8,
         0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
         0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
         0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
         0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
         0x289b7ec6,0xeaa127fa,0xd4ef3085,0x4881d05,
         0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
         0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
         0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
         0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
         0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391]

    def __init__(self, string='', state=None, count=0):
        """md5(string='', state=None, count=0) - Return a new md5
        hash object, optionally initialized to a given internal state
        and count of message bits processed so far, then processes
        string.
        """
        self.count = 0
        self.buffer = b""

        if state is None:
            # initial state defined by standard
            self.state = (0x67452301,
                          0xefcdab89,
                          0x98badcfe,
                          0x10325476,)            
        else:
            self.state = _decode(state, md5.digest_size)
        self.raw_state = self.state
        if count is not None:
            self.count = count
        if string:
            self.update(string)

    def update(self, input):
        """update(input) - Update the md5 object with the string
        arg. Repeated calls are equivalent to a single call with the
        concatenation of all the arguments.
        """
        if isinstance(input, str):
            input = input.encode()
        inputLen = len(input)
        index = int(self.count >> 3) & 0x3F
        self.count = self.count + (inputLen << 3) # update number of bits
        partLen = md5.block_size - index

        # apply compression function to as many blocks as we have
        if inputLen >= partLen:
            self.buffer = self.buffer[:index] + input[:partLen]
            self.state = self.md5_compress(self.state, self.buffer)
            i = partLen
            while i + 63 < inputLen:
                self.state = self.md5_compress(self.state, input[i:i+md5.block_size])
                i = i + md5.block_size
            index = 0
        else:
            i = 0

        # buffer remaining output
        self.buffer = self.buffer[:index] + input[i:inputLen]
        

    def digest(self):
        """digest() - Return the MD5 hash of the strings passed to the
        update() method so far. This is a string of digest_size bytes
        which may contain non-ASCII characters, including null bytes.
        """
        _buffer, _count, _state = self.buffer, self.count, self.state
        self.update(padding(self.count))
        result = self.state
        self.buffer, self.count, self.state = _buffer, _count, _state
        return _encode(result, md5.digest_size)

    def hexdigest(self):
        """hexdigest() - Like digest() except the hash value is
        returned as a string of hexadecimal digits.
        """
        return self.digest().hex()
    
    def md5_compress(self, state, block):
        """md5_compress(state, block) - The MD5 compression function.
        Outputs a 16-byte state based on a 16-byte previous state and a
        512-byte message block.
        """
        a, b, c, d = state
        x = _decode(block, md5.block_size)

        #  Round
        a = FF (a, b, c, d, x[ 0], self.S[0], self.M[0]) # 1
        d = FF (d, a, b, c, x[ 1], self.S[1], self.M[1]) # 2
        c = FF (c, d, a, b, x[ 2], self.S[2], self.M[2]) # 3
        b = FF (b, c, d, a, x[ 3], self.S[3], self.M[3]) # 4
        a = FF (a, b, c, d, x[ 4], self.S[4], self.M[4]) # 5
        d = FF (d, a, b, c, x[ 5], self.S[5], self.M[5]) # 6
        c = FF (c, d, a, b, x[ 6], self.S[6], self.M[6]) # 7
        b = FF (b, c, d, a, x[ 7], self.S[7], self.M[7]) # 8
        a = FF (a, b, c, d, x[ 8], self.S[8], self.M[8]) # 9
        d = FF (d, a, b, c, x[ 9], self.S[9], self.M[9]) # 10
        c = FF (c, d, a, b, x[10], self.S[10], self.M[10]) # 11
        b = FF (b, c, d, a, x[11], self.S[11], self.M[11]) # 12
        a = FF (a, b, c, d, x[12], self.S[12], self.M[12]) # 13
        d = FF (d, a, b, c, x[13], self.S[13], self.M[13]) # 14
        c = FF (c, d, a, b, x[14], self.S[14], self.M[14]) # 15
        b = FF (b, c, d, a, x[15], self.S[15], self.M[15]) # 16

        # Round 2
        a = GG (a, b, c, d, x[ 1], self.S[16], self.M[16]) # 17
        d = GG (d, a, b, c, x[ 6], self.S[17], self.M[17]) # 18
        c = GG (c, d, a, b, x[11], self.S[18], self.M[18]) # 19
        b = GG (b, c, d, a, x[ 0], self.S[19], self.M[19]) # 20
        a = GG (a, b, c, d, x[ 5], self.S[20], self.M[20]) # 21
        d = GG (d, a, b, c, x[10], self.S[21], self.M[21]) # 22
        c = GG (c, d, a, b, x[15], self.S[22], self.M[22]) # 23
        b = GG (b, c, d, a, x[ 4], self.S[23], self.M[23]) # 24
        a = GG (a, b, c, d, x[ 9], self.S[24], self.M[24]) # 25
        d = GG (d, a, b, c, x[14], self.S[25], self.M[25]) # 26
        c = GG (c, d, a, b, x[ 3], self.S[26], self.M[26]) # 27
        b = GG (b, c, d, a, x[ 8], self.S[27], self.M[27]) # 28
        a = GG (a, b, c, d, x[13], self.S[28], self.M[28]) # 29
        d = GG (d, a, b, c, x[ 2], self.S[29], self.M[29]) # 30
        c = GG (c, d, a, b, x[ 7], self.S[30], self.M[30]) # 31
        b = GG (b, c, d, a, x[12], self.S[31], self.M[31]) # 32

        # Round 3
        a = HH (a, b, c, d, x[ 5], self.S[32], self.M[32]) # 33
        d = HH (d, a, b, c, x[ 8], self.S[33], self.M[33]) # 34
        c = HH (c, d, a, b, x[11], self.S[34], self.M[34]) # 35
        b = HH (b, c, d, a, x[14], self.S[35], self.M[35]) # 36
        a = HH (a, b, c, d, x[ 1], self.S[36], self.M[36]) # 37
        d = HH (d, a, b, c, x[ 4], self.S[37], self.M[37]) # 38
        c = HH (c, d, a, b, x[ 7], self.S[38], self.M[38]) # 39
        b = HH (b, c, d, a, x[10], self.S[39], self.M[39]) # 40
        a = HH (a, b, c, d, x[13], self.S[40], self.M[40]) # 41
        d = HH (d, a, b, c, x[ 0], self.S[41], self.M[41]) # 42
        c = HH (c, d, a, b, x[ 3], self.S[42], self.M[42]) # 43
        b = HH (b, c, d, a, x[ 6], self.S[43], self.M[43]) # 44
        a = HH (a, b, c, d, x[ 9], self.S[44], self.M[44]) # 45
        d = HH (d, a, b, c, x[12], self.S[45], self.M[45]) # 46
        c = HH (c, d, a, b, x[15], self.S[46], self.M[46]) # 47
        b = HH (b, c, d, a, x[ 2], self.S[47], self.M[47]) # 48

        # Round 4
        a = II (a, b, c, d, x[ 0], self.S[48], self.M[48]) # 49
        d = II (d, a, b, c, x[ 7], self.S[49], self.M[49]) # 50
        c = II (c, d, a, b, x[14], self.S[50], self.M[50]) # 51
        b = II (b, c, d, a, x[ 5], self.S[51], self.M[51]) # 52
        a = II (a, b, c, d, x[12], self.S[52], self.M[52]) # 53
        d = II (d, a, b, c, x[ 3], self.S[53], self.M[53]) # 54
        c = II (c, d, a, b, x[10], self.S[54], self.M[54]) # 55
        b = II (b, c, d, a, x[ 1], self.S[55], self.M[55]) # 56
        a = II (a, b, c, d, x[ 8], self.S[56], self.M[56]) # 57
        d = II (d, a, b, c, x[15], self.S[57], self.M[57]) # 58
        c = II (c, d, a, b, x[ 6], self.S[58], self.M[58]) # 59
        b = II (b, c, d, a, x[13], self.S[59], self.M[59]) # 60
        a = II (a, b, c, d, x[ 4], self.S[60], self.M[60]) # 61
        d = II (d, a, b, c, x[11], self.S[61], self.M[61]) # 62
        c = II (c, d, a, b, x[ 2], self.S[62], self.M[62]) # 63
        b = II (b, c, d, a, x[ 9], self.S[63], self.M[63]) # 64

        return (0xffffffff & (state[0] + a),
                0xffffffff & (state[1] + b),
                0xffffffff & (state[2] + c),
                0xffffffff & (state[3] + d),)

## end of class


def padding(msg_bits):
    """padding(msg_bits) - Generates the padding that should be
    appended to the end of a message of the given size to reach
    a multiple of the block size."""

    index = int((msg_bits >> 3) & 0x3f)
    if index < 56:
        padLen = (56 - index)
    else:
        padLen = (120 - index)

    # (the last 8 bytes store the number of bits in the message)
    return PADDING[:padLen] + _encode((msg_bits & 0xffffffff, msg_bits>>32), 8)
    
def _encode(input, len):
    k = len >> 2
    res = struct.pack(*("%iI" % k,) + tuple(input[:k]))
    return bytes(res)

def _decode(input, len):
    k = len >> 2
    res = struct.unpack("%iI" % k, input[:len])
    return list(res)


class YRXMD5(md5):
    S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 18, 6, 10, 15, 21]
    

class YRX2MD5(md5):
    S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
    M = [3614090360,5685789145,606105819,3250441966,4118548399,
         1200080426,2821735955,4249261313,1770035416,2336552879,
         4547487822,2304563134,1804603682,4254626195,2792965006,
         1236535329,4129170786,3225465664,643717713,3921069994,
         3593408605,38016083,3634488961,1156354878,568446438,
         3275163606,4107603335,1163531501,2850285829,4243563512,
         1735328473,2368359562,4294588738,2272392833,1839030562,
         4259657740,2763975236,1272893353,4139469664,3200236656,
         681279174,3936430074,3572445317,76029189,3654602809,
         3873151461,530742520,3299628645,4096346452,1126854415,
         2874544791,4237533241,1464885571,1543545348,4293915773,
         2240044497,1873313359,4264344352,2734768916,1309151649,
         4149444226,3174140917,718787259,3951478745]

    def calc_state(self, _0x121ae7, _0x296dcd):
        _0x1375a3 = 2147483584 & _0x121ae7
        _0x12ad0f = 2147483555 & _0x296dcd
        _0x23c56d = 102741724 & _0x121ae7
        _0x4cf0f3 = 1021741824 & _0x296dcd
        _0x49b9d0 = 1073741761 & _0x121ae7
        _0x4c2e60 = 1074511823 & _0x296dcd
        _0xa0dae8 = _0x49b9d0 + _0x4c2e60
        _0x449900 = _0x23c56d & _0x4cf0f3
        if _0x449900:
            return 2147481148 ^ _0xa0dae8 ^ _0x1375a3 ^ _0x12ad0f
        else:
            _0xaf8fc1 = _0x23c56d | _0x4cf0f3
            if _0xaf8fc1:
                _0x410e38 = 1073231824 & _0xa0dae8
                if _0x410e38:
                    return 3221585472 ^ _0xa0dae8 ^ _0x1375a3 ^ _0x12ad0f
                else:
                    return 1073791824 ^ _0xa0dae8 ^ _0x1375a3 ^ _0x12ad0f
                
            else:
                return _0xa0dae8 ^ _0x1375a3 ^ _0x12ad0f

    
    def md5_compress(self, state, block):
        """md5_compress(state, block) - The MD5 compression function.
        Outputs a 16-byte state based on a 16-byte previous state and a
        512-byte message block.
        """
        a, b, c, d = state
        x = _decode(block, md5.block_size)

        #  Round
        a = self.FF (a, b, c, d, x[ 0], self.S[0], self.M[0]) # 1
        d = self.FF (d, a, b, c, x[ 1], self.S[1], self.M[1]) # 2
        c = self.FF (c, d, a, b, x[ 2], self.S[2], self.M[2]) # 3
        b = self.FF (b, c, d, a, x[ 3], self.S[3], self.M[3]) # 4
        a = self.FF (a, b, c, d, x[ 4], self.S[4], self.M[4]) # 5
        d = self.FF (d, a, b, c, x[ 5], self.S[5], self.M[5]) # 6
        c = self.FF (c, d, a, b, x[ 6], self.S[6], self.M[6]) # 7
        b = self.FF (b, c, d, a, x[ 7], self.S[7], self.M[7]) # 8
        a = self.FF (a, b, c, d, x[ 8], self.S[8], self.M[8]) # 9
        d = self.FF (d, a, b, c, x[ 9], self.S[9], self.M[9]) # 10
        c = self.FF (c, d, a, b, x[10], self.S[10], self.M[10]) # 11
        b = self.FF (b, c, d, a, x[11], self.S[11], self.M[11]) # 12
        a = self.FF (a, b, c, d, x[12], self.S[12], self.M[12]) # 13
        d = self.FF (d, a, b, c, x[13], self.S[13], self.M[13]) # 14
        c = self.FF (c, d, a, b, x[14], self.S[14], self.M[14]) # 15
        b = self.FF (b, c, d, a, x[15], self.S[15], self.M[15]) # 16

        # Round 2
        a = self.GG (a, b, c, d, x[ 1], self.S[16], self.M[16]) # 17
        d = self.GG (d, a, b, c, x[ 6], self.S[17], self.M[17]) # 18
        c = self.GG (c, d, a, b, x[11], self.S[18], self.M[18]) # 19
        b = self.GG (b, c, d, a, x[ 0], self.S[19], self.M[19]) # 20
        a = self.GG (a, b, c, d, x[ 5], self.S[20], self.M[20]) # 21
        d = self.GG (d, a, b, c, x[10], self.S[21], self.M[21]) # 22
        c = self.GG (c, d, a, b, x[15], self.S[22], self.M[22]) # 23
        b = self.GG (b, c, d, a, x[ 4], self.S[23], self.M[23]) # 24
        a = self.GG (a, b, c, d, x[ 9], self.S[24], self.M[24]) # 25
        d = self.GG (d, a, b, c, x[14], self.S[25], self.M[25]) # 26
        c = self.GG (c, d, a, b, x[ 3], self.S[26], self.M[26]) # 27
        b = self.GG (b, c, d, a, x[ 8], self.S[27], self.M[27]) # 28
        a = self.GG (a, b, c, d, x[13], self.S[28], self.M[28]) # 29
        d = self.GG (d, a, b, c, x[ 2], self.S[29], self.M[29]) # 30
        c = self.GG (c, d, a, b, x[ 7], self.S[30], self.M[30]) # 31
        b = self.GG (b, c, d, a, x[12], self.S[31], self.M[31]) # 32

        # Round 3
        a = self.HH (a, b, c, d, x[ 5], self.S[32], self.M[32]) # 33
        d = self.HH (d, a, b, c, x[ 8], self.S[33], self.M[33]) # 34
        c = self.HH (c, d, a, b, x[11], self.S[34], self.M[34]) # 35
        b = self.HH (b, c, d, a, x[14], self.S[35], self.M[35]) # 36
        a = self.HH (a, b, c, d, x[ 1], self.S[36], self.M[36]) # 37
        d = self.HH (d, a, b, c, x[ 4], self.S[37], self.M[37]) # 38
        c = self.HH (c, d, a, b, x[ 7], self.S[38], self.M[38]) # 39
        b = self.HH (b, c, d, a, x[10], self.S[39], self.M[39]) # 40
        a = self.HH (a, b, c, d, x[13], self.S[40], self.M[40]) # 41
        d = self.HH (d, a, b, c, x[ 0], self.S[41], self.M[41]) # 42
        c = self.HH (c, d, a, b, x[ 3], self.S[42], self.M[42]) # 43
        b = self.HH (b, c, d, a, x[ 6], self.S[43], self.M[43]) # 44
        a = self.HH (a, b, c, d, x[ 9], self.S[44], self.M[44]) # 45
        d = self.HH (d, a, b, c, x[12], self.S[45], self.M[45]) # 46
        c = self.HH (c, d, a, b, x[15], self.S[46], self.M[46]) # 47
        b = self.HH (b, c, d, a, x[ 2], self.S[47], self.M[47]) # 48

        # Round 4
        a = self.II (a, b, c, d, x[ 0], self.S[48], self.M[48]) # 49
        d = self.II (d, a, b, c, x[ 7], self.S[49], self.M[49]) # 50
        c = self.II (c, d, a, b, x[14], self.S[50], self.M[50]) # 51
        b = self.II (b, c, d, a, x[ 5], self.S[51], self.M[51]) # 52
        a = self.II (a, b, c, d, x[12], self.S[52], self.M[52]) # 53
        d = self.II (d, a, b, c, x[ 3], self.S[53], self.M[53]) # 54
        c = self.II (c, d, a, b, x[10], self.S[54], self.M[54]) # 55
        b = self.II (b, c, d, a, x[ 1], self.S[55], self.M[55]) # 56
        a = self.II (a, b, c, d, x[ 8], self.S[56], self.M[56]) # 57
        d = self.II (d, a, b, c, x[15], self.S[57], self.M[57]) # 58
        c = self.II (c, d, a, b, x[ 6], self.S[58], self.M[58]) # 59
        b = self.II (b, c, d, a, x[13], self.S[59], self.M[59]) # 60
        a = self.II (a, b, c, d, x[ 4], self.S[60], self.M[60]) # 61
        d = self.II (d, a, b, c, x[11], self.S[61], self.M[61]) # 62
        c = self.II (c, d, a, b, x[ 2], self.S[62], self.M[62]) # 63
        b = self.II (b, c, d, a, x[ 9], self.S[63], self.M[63]) # 64
        print(self.raw_state)
        return (self.calc_state(a, self.raw_state[0]),
            self.calc_state(b, self.raw_state[1]),
            self.calc_state(c, self.raw_state[2]),
            self.calc_state(d, self.raw_state[3]),)

    
    def FF(self, _0x3513b1, _0x3d7730, _0x30f456, _0x2c0214, _0x56dd83, _0x2b4b6d, _0x5e4436):
        _0x38cdbc = F(_0x3d7730, _0x30f456, _0x2c0214)
        _0x18946f = self.calc_state(_0x38cdbc, _0x56dd83)
        _0x46dff6 = self.calc_state(_0x18946f, _0x5e4436)
        _0x3cce00 = self.calc_state(_0x3513b1, _0x46dff6)
        _0x2e6bc6 = ROTATE_LEFT(_0x3cce00, _0x2b4b6d)
        return ctypes.c_int32(self.calc_state(_0x2e6bc6, _0x3d7730)).value

    def GG(self, _0x323392, _0x4f9c5e, _0x51f4c6, _0x221895, _0x72b89f, _0x8ade27, _0x445760):
        _0x5daa46 = G(_0x4f9c5e, _0x51f4c6, _0x221895)
        _0x2178f8 = self.calc_state(_0x5daa46, _0x72b89f)
        _0x13a5be = self.calc_state(_0x2178f8, _0x445760)
        _0x4cee32 = self.calc_state(_0x323392, _0x13a5be)
        _0x3beb2d = ROTATE_LEFT(_0x4cee32, _0x8ade27)
        return ctypes.c_int32(self.calc_state(_0x3beb2d, _0x4f9c5e)).value
    
    def HH(self, _0x1bcc38, _0x4dfe6c, _0x3ce2ca, _0x59a6ec, _0x1b8fdb, _0x1aca8e, _0xb36f77):
        _0x462ced = H(_0x4dfe6c, _0x3ce2ca, _0x59a6ec)
        _0xd40246 = self.calc_state(_0x462ced, _0x1b8fdb)
        _0x2194a2 = self.calc_state(_0xd40246, _0xb36f77)
        _0x2a1a9b = self.calc_state(_0x1bcc38, _0x2194a2)
        _0x5b25cf = ROTATE_LEFT(_0x2a1a9b, _0x1aca8e)
        return ctypes.c_int32(self.calc_state(_0x5b25cf, _0x4dfe6c)).value
    
    def II(self, _0x789423, _0x40a8a0, _0x19f482, _0x2a87e9, _0x2ff686, _0x4440e5, _0x300cc2):
        _0x35b48c = I(_0x40a8a0, _0x19f482, _0x2a87e9)
        _0x44f109 = self.calc_state(_0x35b48c, _0x2ff686)
        _0x23f73c = self.calc_state(_0x44f109, _0x300cc2)
        _0x553d2a = self.calc_state(_0x789423, _0x23f73c)
        _0x28a0db = ROTATE_LEFT(_0x553d2a, _0x4440e5)
        return ctypes.c_int32(self.calc_state(_0x28a0db, _0x40a8a0)).value
    






def test(input=""):
    """test(input): displays results of input hashed with our md5
    function and the standard Python hashlib implementation
    """
    print(repr(md5(input).hexdigest()))
    import hashlib
    print(repr(hashlib.md5(input.encode()).hexdigest()))

if __name__=="__main__":
    test("中国")
    state = b'\x01#Eg\x80\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10'
    S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 18, 6, 10, 15, 21]
    m = md5("test", state)
    print(m.hexdigest())
    state = b"\x93\xae\xa7\x88\xb3Oy'~\xfe\x90\r\xc6\xc3[J"
    data = "1685669093476/api/match2023/2?page=1"
    data = '1685699820765/api/match2023/2?page=1'
    m = YRX2MD5(data, state=state, count=0)
    print(m.hexdigest())
