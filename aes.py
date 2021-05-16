# Inspired with https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf

import base64
import sys
import binascii
import numpy as np
import getopt
import os

# np.set_printoptions(formatter={'int':lambda x: format(x, '#010b')})
np.set_printoptions(formatter={'int':lambda x: hex(int(x))})

bs = 16
# Can't find anything to create these two tables by myself... so ...
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16
]
sboxInv = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d
]


def gmul(a: int, b: int) -> int:
    """
    Get product of two integers, by Galois Field
    ( https://en.wikipedia.org/wiki/Finite_field_arithmetic )

    Parameters
    ---
    a (int)
        First int
    b (int)
        Second int

    Result
    ---
    int
    """
    p = 0
    while a and b:
        if b & 1:
            p ^= a
        if a & 0x80:
            a = (a << 1) ^ 0x11b
        else:
            a = a << 1
        b = b >> 1
    return p


def bytesSub(data: np.matrix) -> np.matrix:
    """
    Return matrix of substitutes bytes s-box mode
    for a given matrix.
    Useful for encryption of AES-ECB.

    Parameters
    ---
    data (np.matrix)
        Matrix to get substitutes bytes from

    Result
    ---
    np.matrix
    """
    return np.vectorize(lambda x: sbox[x])(data)


def bytesSubInv(data: np.matrix) -> np.matrix:
    """
    Return matrix of substitutes bytes s-box-inverse mode
    for a given matrix. 
    Useful for decryption of AES-ECB.

    Parameters
    ---
    data (np.matrix)
        Matrix to get substitutes bytes inverse from

    Result
    ---
    np.matrix
    """
    return np.vectorize(lambda x: sboxInv[x])(data)


def bitRotate(i: int, c: int, right: bool = False) -> int:
    """
    Rotate bits of a given integer, c-given times.
    e.g.
    bitRotateLeft(78, 3)
    == 01001110 (78)
    => 01110010 (116)

    Parameters
    ---
    i (int)
        Integer to rotate
    c (int)
        Times of rotate to process
    right (bool)
        By default, False to Left.
        Set to True to rotate to right.

    Result
    ---
    int
    """
    if right:
        return ((i >> c) | (i << 8 - c)) & 0xff
    else:
        return ((i << c) | (i >> 8 - c)) & 0xff


def rotate(v: np.matrix, c: int, right: bool = False) -> np.matrix:
    """
    Rotate a given 1D-array, c-given times.
    e.g.
    rotate([1,2,3,4,5,6],2)
    => [3,4,5,6,1,2]

    Parameters
    ---
    v (np.matrix)
        1D-array to rotate
    c (int)
        Times of rotate to process
    right (bool)
        By default, False to Left.
        Set to True to rotate to right.

    Result
    ---
    np.ndarrray 
    """
    va = np.array(v)[0]
    if right:
        return np.matrix(np.concatenate((va[-c:], va[:-c])))
    else:
        return np.matrix(np.concatenate((va[c:], va[:c])))


def splitBytes(data: bytes, bs: int) -> list:
    """
    Split bytes into bs-sized chunks, and return a list.

    Parameters
    ---
    data (bytes)
        Given bytes to split into chunk
    bs (int)
        Size of chunks

    Result
    ---
    list
    """
    return [data[i:i+bs] for i in range(0, len(data), bs)]


def bytesToMatrix(data: bytes, size: int) -> np.matrix:
    """
    Return sized matrix of the given data bytes.

    Parameters
    ---
    data (bytes)
        data to transform into matrix
    size (int)
        Size of the matrix

    Result
    ---
    np.matrix
    """
    return np.matrix([[j for j in i] for i in splitBytes(data, size)])


def shiftRows(data: np.matrix, b_decrypt: bool = False) -> np.matrix:
    """
    Return matrix of shifted rows

    Parameters
    ---
    data (np.matrix)
        matrix to shift
    decrypt (bool)
        Set True to enable decryption sens

    Result
    ---
    np.matrix
    """
    return np.concatenate([rotate(data[i], i, b_decrypt) for i in range(len(data))])


def mixColumn(col: np.matrix, b_decrypt: bool = False) -> np.matrix:
    """
    Return the mixed (or unmixed if decryption) of the given matrix.

    Parameters
    ---
    col (np.matrix)
        column of matrix to mix/unmix

    Result
    ---
    np.matrix
    """
    m = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2]
        ]
    m_decrypt = [
        [14, 11, 13, 9],
        [9, 14, 11, 13],
        [13, 9, 14, 11],
        [11, 13, 9, 14]
        ]
    m_used = m_decrypt if b_decrypt else m
    c = np.vectorize(lambda a, b: gmul(a, b))(col, m_used)
    return np.bitwise_xor.reduce(c.getT())


def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    w1 = a[0] ^ t ^ xtime(a[0] ^ a[1])
    w2 = a[1] ^ t ^ xtime(a[1] ^ a[2])
    w3 = a[2] ^ t ^ xtime(a[2] ^ a[3])
    w4 = a[3] ^ t ^ xtime(a[3] ^ u)
    return np.matrix([[w1, w2, w3, w4]])


def mixColumns(data: np.matrix, decrypt: bool = False) -> np.matrix:
    """
    Return the mixed (or unmixed if decryption) of the given matrix

    Parameters
    ---
    data (np.matrix)
        Matrix to mix/unmix
    decrypt (bool=False)
        Set to True to enable decryption

    Result
    ---
    np.matrix
    """
    ar_concat = []
    for i in range(len(data)):
        ar_concat.append(mix_single_column(np.asarray(data.getT())[i]))
    ar_concat = np.concatenate(ar_concat)
    return np.concatenate(ar_concat).getT()


def mixColumns_bak(data: np.matrix, decrypt: bool = False) -> np.matrix:
    """
    Return the mixed (or unmixed if decryption) of the given matrix

    Parameters
    ---
    data (np.matrix)
        Matrix to mix/unmix
    decrypt (bool=False)
        Set to True to enable decryption

    Result
    ---
    np.matrix
    """
    return np.concatenate([mixColumn(i) for i in data.getT()]).getT()


def getRoundConstant(n: int) -> int:
    """
    Calculate the Round Constant of the AES key schedule,
    following this :
    https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants

    Parameters
    ---
    n (int)
        Number of the round
    """
    if n == 1:
        return 1
    else:
        res = getRoundConstant(n-1)
        if res < 0x80:
            return 2*res
        else:
            return (2*res) ^ 0x11b


def gKey(row: np.matrix, round_constant: int) -> np.matrix:
    """
    Return the g() matrix, required for extending keys.

    Parameters
    ---
    row (np.matrix)
        row to scramble
    round_constant (int)
        Round Constant to apply
    Result
    ---
    matrix
    """
    g = rotate(row, 1)
    g = bytesSub(g)
    g = g ^ [round_constant, 0, 0, 0]
    return g


def extendKey(key: np.matrix) -> list:
    """
    Return a list of matrix of extended keys from a given key

    Parameters
    ---
    key (np.matrix)
        Original key to extend

    Result
    ---
    list
    """
    extended = [key]
    for i in range(1, 11):
        w = extended[-1]
        w4 = w[0] ^ gKey(w[3], getRoundConstant(i))
        w5 = w4 ^ w[1]
        w6 = w5 ^ w[2]
        w7 = w6 ^ w[3]
        extended.append(np.concatenate((w4, w5, w6, w7)))
    return extended


def decryptBlock(data: np.matrix, key: np.matrix) -> np.matrix:
    encoded = data.getT()
    # print("Decrypting ")
    # print(encoded)
    keys = extendKey(key)
    for i in range(len(keys)-1, 0, -1):
        # print("Applying key {}".format(keys[i].flatten()))
        encoded = encoded ^ keys[i].getT()
        # print("{} Befor RoundKey  {}".format(i, encoded.flatten()))
        if i < len(keys)-1:
            # If we run mixColumns 4 times, matrix doesnt change
            for j in range(3):
                encoded = mixColumns(encoded)
            # print("{} Befor  mix      {}".format(i, encoded.flatten()))
        encoded = shiftRows(encoded, True)
        # print("{} Befor shift row {}".format(i, encoded.flatten()))
        encoded = bytesSubInv(encoded)
        # print("{} Before subst    {}".format(i, encoded.flatten()))
        # == ENCRYPTING 
    # print(encoded)
    encoded = encoded ^ key.getT()
    # print(encoded)
    return encoded.getT().tobytes()[::8]


def encryptBlock(data: np.matrix, key: np.matrix) -> np.matrix:
    encoded = data.getT() ^ key.getT()
    keys = extendKey(key)
    for i in range(1, len(keys)):
        encoded = bytesSub(encoded)
        # print("{} After subst     {}".format(i, encoded.flatten()))
        encoded = shiftRows(encoded)
        # print("{} After shift row {}".format(i, encoded.flatten()))
        if i < len(keys)-1:
            encoded = mixColumns(encoded)
            # print("{} After  mix      {}".format(i, encoded.flatten()))
        # print("Applying key {}".format(keys[i].flatten()))
        encoded = encoded ^ keys[i].getT()
        # print("{} After RoundKey  {}".format(i, encoded.flatten()))
    return encoded.getT().tobytes()[::8]


def decrypt(data: bytes, key: bytes) -> bytes:
    chunks = splitBytes(data, bs)
    decrypted = b""
    m_key = bytesToMatrix(key, 4)
    for c in chunks:
        m_cipher = bytesToMatrix(c, 4)
        decrypted += decryptBlock(m_cipher, m_key)
    return decrypted


def encrypt(data: bytes, key: bytes) -> bytes:
    chunks = splitBytes(data, bs)
    encrypted = b""
    m_key = bytesToMatrix(key, 4)
    for c in chunks:
        m_plain = bytesToMatrix(c, 4)
        encrypted += encryptBlock(m_plain, m_key)
    return encrypted


def forceBytes(data):
    if type(data) == str:
        return data.encode('iso-8859-1')
    return data


def forceStr(data):
    if type(data) == bytes:
        return data.decode('iso-8859-1')
    return data


def readInput(data: bytes, mode: str) -> bytes:
    if mode == "b64":
        return base64.b64decode(forceStr(data))
    elif mode == "hex":
        return bytes(bytearray.fromhex(forceStr(data)))
    elif mode == "raw":
        return forceBytes(data)


def usage():
    print("""Usage of AES-ECB
    Example :
    {} -k "Thats my Kung Fu" -d "Two One Nine Two" -o output_file.txt
    {} -k key_file.txt -d data_file.txt --decrypt

    -k (Required) : File containing the key, or key between quotes (i.e example)
                    If it's not equal to 16 bytes, it will be truncated or padded.

    -d (Required) : File containing data to encrypt/decrypt, or data directly.
                    Can be text between quotes if encrypting
                    If it's not a multiple of 16 bytes, it will be padded with '\x00'.
    
    --dmode (Optional) : raw/b64/hex : Specify the data-type on input

    --decrypt (Optional) : Enable decryption instead of encryption.
    
    -o (Optional) : Specify the output file. If not specified, the ouput will be on stdout as hexadecimal.
    """.format(sys.argv[0], sys.argv[0]))


def main():
    decryption = False
    arg_key = ""
    arg_data = ""
    output_file = ""
    dmode = "raw"
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hk:d:o:", ["decrypt", "dmode="])
        for o, a in opts:
            if o in ("-h"):
                usage()
                sys.exit()
            elif o in ("-k"):
                arg_key = a
            elif o in ("-d"):
                arg_data = a
            elif o in ("-o"):
                output_file = a
            elif o in ("--decrypt"):
                decryption = True
            elif o in ("--dmode"):
                dmode = a
                if a not in ("b64", "hex", "raw"):
                    raise Exception("Unknow Mode !")
            else:
                assert False, "unhandled option"
        if arg_key == "" or arg_data == "":
            raise Exception("Key and data required !")
    except Exception as exc:
        print(exc.args[0])
        usage()
        sys.exit(2)
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    if os.path.exists(arg_data):
        arg_data = open(arg_data, 'rb').read()
    else:
        arg_data = arg_data.encode()
    if os.path.exists(arg_key):
        arg_key = open(arg_key, 'rb').read()
    else:
        arg_key = arg_key.encode()

    arg_data = readInput(arg_data, dmode)

    if decryption:
        if len(arg_data) % bs != 0:
            print("Data lenght is not corresponding to the modulo block size of {}.".format(bs))
            exit(2)
    else:
        diff = bs - (len(arg_data) % bs)
        arg_data += bytes([diff]) * diff

    if len(arg_key) != bs:
        if len(arg_key) < 16:
            print("Key length is shorter than {}. It will be padded.".format(bs))
            arg_key += b'\x00' * (bs - arg_key)
        else:
            print("Key length is longer than {}. It will be truncated".format(bs))
            arg_key = arg_key[:bs]

    if decryption:
        res = decrypt(arg_data, arg_key)
    else:
        res = encrypt(arg_data, arg_key)
    if output_file != "":
        open(output_file, 'wb+').write(res)
    else:
        if decryption:
            print(res)
        else:
            print(binascii.hexlify(res))


if __name__ == "__main__":
    main()
