import base64
import os
import random
from Crypto.Util.number import long_to_bytes,bytes_to_long
from Crypto.Util.Padding import unpad,pad

import binascii
# pip install based58
import based58


STANDARD_ALPHABET = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHABET =   b'+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
ENCODE_TRANS = bytes.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
DECODE_TRANS = bytes.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)

def xxbase64_encode(input:bytes)->bytes:
  return base64.b64encode(input).translate(ENCODE_TRANS)

def xxbase64_decode(input:bytes)->bytes:
  pad=len(input)%4
  if pad!=0:
      input+=b'='*pad
  return base64.b64decode(input.translate(DECODE_TRANS))

def int_to_bytes(n:int,order='little')->bytes:
    # 获取整数的位长度
    bit_length = n.bit_length()
    # 计算所需的最小字节数
    byte_length = (bit_length + 7) // 8
    # 转换为字节序列，使用大端字节序
    byte_array = n.to_bytes(byte_length, byteorder=order)
    return byte_array

def Reverse_dw(data:bytes):
    ret=b''
    for i in range(0,len(data),4):
        ret+=data[i:i+4][::-1]
    return ret

BS_PK=b'++11Ik:7EFlNLs6Yqc3p-LtUOXBElimekQm8e3BTSeGhxhlpmVDeVVrrUAkLTXpZ7mK6jAPAOhyHiokPtYfmokklPELfOxt1s5HJmAnl-5r8YEvsQXY8-dm6EFwYJlXgWOCutNn2+FsvA7EXvM-2xZ1MW8LiGeYuXCA6Yt2wTuU4YWM+ZUBkIGEs1QRNRYIeGB9GB9YsS8U2-Z3uunZPgnA5pF+E8BRwYz9ZE--VFeKCPamspG7tdvjA3AJNRNrCVmJvwq5SqgEQwINdcmwwjmc4JetVK76og5A5sPOIXSwOjlYK+Sm8rvlJZoxh0XFfyioHz48JV3vXbBKjgAlPAc7Npn+wk'
# _bs_e=b'++11Ik'
# _bs_n= b'7EFlNLs6Yqc3p-LtUOXBElimekQm8e3BTSeGhxhlpmVDeVVrrUAkLTXpZ7mK6jAPAOhyHiokPtYfmokklPELfOxt1s5HJmAnl-5r8YEvsQXY8-dm6EFwYJlXgWOCutNn2+FsvA7EXvM-2xZ1MW8LiGeYuXCA6Yt2wTuU4YWM+ZUBkIGEs1QRNRYIeGB9GB9YsS8U2-Z3uunZPgnA5pF+E8BRwYz9ZE--VFeKCPamspG7tdvjA3AJNRNrCVmJvwq5SqgEQwINdcmwwjmc4JetVK76og5A5sPOIXSwOjlYK+Sm8rvlJZoxh0XFfyioHz48JV3vXbBKjgAlPAc7Npn+wk'
_bs_e,_bs_n=BS_PK.split(B':')
_bs_e=xxbase64_decode(_bs_e)
_bs_n=xxbase64_decode(_bs_n)
_bs_e_le=Reverse_dw(_bs_e)
_bs_n_le=Reverse_dw(_bs_n)
E=int.from_bytes(_bs_e_le,'little')
N=int.from_bytes(_bs_n_le,'little')
#BeyondCompareKeyMaker_windows_amd64.exe
#5D0AB5                 call    sub_5E5640      ; get d
_bs_d=binascii.a2b_hex('4860d32b474ff398b0058aaf111fe820f8bebad4342cb40b6fd7652b37a92cf077d58ca7374dcf65615fe846e73ababe6a729a59ebdd8b980bbeb47f3ef8041decc465118a40d76293b5fce1271d87865b3f1dc116f2637d8dfa338a5103ef14e9c28f620c325c1e241e2bfa9258d16b1239c5c06ce13ec2fe377fac038a0ff0eb0f5910018724fd4bf429f1c0fac86af083acdab388c18e281a5ea9976b385e6c0383485135f1e68cd7a3c0ab6d36b07aa1404e081083158e523129ace077972fc3bd9424fbe86c64b33e8916e0a15c0f5a346e2260fb565ee00741268e6987b978df646c81bd72b55e0ea94f5f51956bf80ffc4c51f6fcaaab96135c888523')
D=bytes_to_long(_bs_d)

def rsa_pri_enc(i_msg:int)->int:
    enc=pow(i_msg,D,N)
    return enc

def rsa_pub_dec(i_msg:int)->int:
    dec=pow(i_msg,E,N)
    return dec

def gen_cstr(data:bytes)->bytes:
    ret=b'\x00'
    sz=len(data)
    if sz:
        ret=len(data).to_bytes(1,'little')+data
    return ret
class LIC_TYPE:
    WINDOWS=4
    LINUX=8
    MACOS=0x10
    PRO=0x21
def set_lic(usernumber=99999,username='kunkun',atsite='ikun'):

    lic=b'\x04SCTR'
    #
    lic+=gen_cstr('')
    lic+=gen_cstr('')
    lic+=gen_cstr('')
    lic+=gen_cstr('')
    lic+=gen_cstr('')
    #
    lic+=b'\x01'
    lic+=gen_cstr(b'73051')
    lic+=gen_cstr(f'{usernumber}|{atsite}'.encode())
    lic+=b'\x06'
    #license type
    '''
    4    windows
    8    linux
    0x10 macos
    0x21 Pro Edition

    0x3d==>Pro Edition for Windows/Linux/macOS
    '''
    lic+=(LIC_TYPE.PRO|LIC_TYPE.WINDOWS|LIC_TYPE.LINUX|LIC_TYPE.MACOS).to_bytes(1,'little')#b'\x3d'

    lic+= os.urandom(5)

    lic+=b'\x09'+b'-'.join([str(random.randint(1000,10000)).encode()  for _ in range(2) ] )

    lic+=gen_cstr(b'0')
    lic+=gen_cstr(b'30')
    lic+=gen_cstr(b'15')

    lic+=gen_cstr(f'{username}'.encode())

    lic+=gen_cstr(b'0')
    lic+=gen_cstr(b'0')

    lic=pad(lic,0xff)
    return lic

def keygen(usernumber=99999,username='kunkun',atsite='ikun',):
    lic=set_lic(usernumber,username,atsite)
    # print('plain lic:',lic.hex())
    imsg=int.from_bytes(lic,'little')
    i_data=rsa_pri_enc(imsg)
    data=int_to_bytes(i_data)
    # print('rsa_pri_enc lic:',data.hex())
    lickey=based58.b58encode(data)
    lickey='--- BEGIN LICENSE KEY ---\r\n'+lickey.decode()+'\r\n--- END LICENSE KEY -----\r\n'
    print('%s\n\n'%lickey)
    return lickey

def dec_lickey(data:bytes):
    licdata=based58.b58decode(data)
    imsg=int.from_bytes(licdata,'little')
    i_lic=rsa_pub_dec(imsg)
    lic=int_to_bytes(i_lic)
    print('original lic:',lic.hex())
    pass

if __name__ == '__main__':
    key=keygen()
    # key=key.replace('--- BEGIN LICENSE KEY ---\r\n','')
    # key=key.replace('\r\n--- END LICENSE KEY -----\r\n','')
    # dec_lickey(key.encode())
    pass

