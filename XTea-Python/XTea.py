#-*- coding: UTF-8 -*-
from ctypes import c_int32
import base64

#KEY
key = [0x789f5645, 0xf68bd5a4,0x81963ffa, 0xabcdef12]
#TIMES
times = 32

#Tea加密
def encryptByTea(value,key,times):
    y = c_int32(value[0]);
    z = c_int32(value[1]);
    sum = c_int32(0);
    delta = 0x9E3779B9;
    w = [0, 0]
    while (times > 0):
        sum.value += delta
        y.value += (z.value << 4) + key[0] ^ z.value + sum.value ^ (z.value >> 5) + key[1]
        z.value += (y.value << 4) + key[2] ^ y.value + sum.value ^ (y.value >> 5) + key[3]
        times -= 1
    w[0] = y.value
    w[1] = z.value
    return w[0],w[1]

#Tea解密
def decryptByTea(value,key,times):
    y = c_int32(value[0]);
    z = c_int32(value[1]);
    sum = c_int32(0);
    delta = 0x9E3779B9;
    if times == 32:
        sum = 0xC6EF3720
    elif times == 16:
        sum = 0xE3779B90
    else:
        sum = delta * times
    w = [0, 0]
    while (times > 0):
        z.value -= ((y.value << 4) + key[2]) ^ (y.value + sum) ^ ((y.value >> 5) + key[3]);
        y.value -= ((z.value << 4) + key[0]) ^ (z.value + sum) ^ ((z.value >> 5) + key[1]);
        sum -= delta;
        times -= 1;
    w[0] = y.value
    w[1] = z.value
    return w[0],w[1]

#Int转Byte
def intToByte(content):
    result = [];
    for i in range(0,len(content)):
        result.append((content[i] >> 24) & 0xff)
        result.append((content[i] >> 16) & 0xff)
        result.append((content[i] >> 8) & 0xff)
        result.append((content[i]) & 0xff)
    return result;

#Byte转int
def byteToInt(content):
    result = [];
    for i in range(0,len(content),4):
        result.append(content[i + 3] | content[i + 2] << 8 | content[i + 1] << 16 | content[i] << 24)
    return result;

#字节数组转为16进制列表
def bytes2hex(bs):
    hexList = []
    for i in bs:
        temphex =  hex(i)
        if len(temphex) == 3:
            temphex = "0"+temphex
        hexList.append(temphex)
    return hexList

#16进制转10进制
def hex2bytes(hex):
    if len(hex) % 2 != 0:
        hex = "0" + hex
    val = []
    for i in range(0,len(hex),2):
        val.append(int(hex[i:i+2],16))
    return val

def encryptByBase64Tea(message):
    # 转成bytes数组
    strByte = bytes(message, encoding="utf8")
    #字节数组转为16进制列表
    hexList = bytes2hex(strByte)
    #16进制列表转化为字符串
    hexStr = "".join(hexList).upper().replace("0X","")
    #16进制字符串转字节数组
    str2Byte = bytes(hexStr, encoding="utf8")
    #str2Byte位数与它8的倍数的差
    n = 8 - len(str2Byte) % 8;
    #若str2Byte的位数不足8的倍数,需要在list前填充位数，第一位为n,第2至n-1位为0
    beforeEncryptList = []
    for i in range(0,len(str2Byte)+n):
        if i==0:
            beforeEncryptList.append(n)
        elif i<n:
            beforeEncryptList.append(0)
        else:
            beforeEncryptList.append(str2Byte[i-n])

    #TEA加密list
    encryptList = []
    for i in range(0,len(beforeEncryptList),8):
        tempInt = byteToInt(beforeEncryptList[i:i+8])
        tempEncrypt1,tempEncrypt2 = encryptByTea(tempInt,key,times)
        encryptList.append(tempEncrypt1)
        encryptList.append(tempEncrypt2)

    #列表转字节值的列表
    byteValue = intToByte(encryptList)
    # 把int的列表转字节数组
    int2Byte = bytes(byteValue)
    #base64
    base64Str = str(base64.b64encode(int2Byte))
    #把+号替换成%2B
    teaStr = base64Str[2:len(base64Str)-1].replace("+","%2B")
    return teaStr

def decryptByBase64Tea(message):
    #把%2B替换成+号
    teaStr = message.replace("%2B","+");
    #base64
    base64Bytes = base64.decodebytes(bytes(teaStr, encoding="utf8"))
    #字节数组转化成整型数组
    byte2Int = byteToInt(base64Bytes)
    #TEA解密
    decrypTeaList = []
    for i in range(0,len(byte2Int),2):
        tempDencrypt1,tempDencrypt2 = decryptByTea(byte2Int[i:i+2],key,times)
        decrypTeaList.append(tempDencrypt1)
        decrypTeaList.append(tempDencrypt2)
    #整型转字节
    byteValue = intToByte(decrypTeaList)
    n = byteValue[0]
    #转字节数组
    tempBytes = bytes(byteValue[n:len(byteValue)]).decode('utf8')
    hexBytes = bytes(hex2bytes(tempBytes))
    deStr = hexBytes.decode('utf8')
    return deStr

message = "XTea加密运算测试";
enTea = encryptByBase64Tea(message)
print(enTea)
deTea = decryptByBase64Tea(enTea)
print(deTea)
