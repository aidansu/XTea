package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"
)

// KEY
var key = []int{0x789f5645, 0xf68bd5a4, 0x81963ffa, 0xabcdef12}

// TIMES
const times int = 32

// Tea加密
func encryptByTea(value []int, key []int, times int) (a int, b int) {
	y := int32(value[0])
	z := int32(value[1])
	var sum int32
	var delta int32 = -1640531527 //0x9E3779B9
	for times > 0 {
		sum += delta
		y += ((z << 4) + int32(key[0])) ^ (z + sum) ^ ((z >> 5) + int32(key[1]))
		z += ((y << 4) + int32(key[2])) ^ (y + sum) ^ ((y >> 5) + int32(key[3]))
		times--
	}
	a = int(y)
	b = int(z)
	return
}

// Tea解密
func decryptByTea(value []int, key []int, times int) (a int, b int) {
	y := int32(value[0])
	z := int32(value[1])
	var sum int32
	var delta int32 = -1640531527 //0x9E3779B9
	if times == 32 {
		sum = -957401312 //0xC6EF3720
	} else if times == 16 {
		sum = -478700656 //0xE3779B90
	} else {
		sum = delta * int32(times)
	}
	for times > 0 {
		z -= ((y << 4) + int32(key[2])) ^ (y + sum) ^ ((y >> 5) + int32(key[3]))
		y -= ((z << 4) + int32(key[0])) ^ (z + sum) ^ ((z >> 5) + int32(key[1]))
		sum -= delta
		times--
	}
	a = int(y)
	b = int(z)
	return
}

// byte转16进制字符串
func byteToHex(data []byte) string {
	buffer := new(bytes.Buffer)
	for _, b := range data {
		s := strconv.FormatInt(int64(b&0xff), 16)
		if len(s) == 1 {
			buffer.WriteString("0")
		}
		buffer.WriteString(s)
	}
	return strings.ToUpper(buffer.String())
}

// 16进制字符串转byte
func hexToByte(hexStr string) []byte {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	var byteValue []byte
	for i := 0; i < len(hexStr); i = i + 2 {
		val, parseIntErr := strconv.ParseInt(hexStr[i:i+2], 16, 32) //字串到数据整型
		if parseIntErr != nil {
			log.Println("parseIntErr = ", parseIntErr)
			return byteValue
		}
		byteValue = append(byteValue, byte(val))
	}
	return byteValue
}

// Int转Byte
func intToByte(content []int) []byte {
	var result []byte
	for i := 0; i < len(content); i++ {
		result = append(result, byte((content[i]>>24)&0xff))
		result = append(result, byte((content[i]>>16)&0xff))
		result = append(result, byte((content[i]>>8)&0xff))
		result = append(result, byte((content[i])&0xff))
	}
	return result
}

// Byte转Int
func byteToInt(content []byte) []int {
	var result []int
	for i := 0; i < len(content); i = i + 4 {
		result = append(result, int(content[i+3])|int(content[i+2])<<8|int(content[i+1])<<16|int(content[i])<<24)
	}
	return result
}

func encryptByBase64Tea(message string) (enTea string) {
	// string转byte[]
	xByte := []byte(message)
	// byte[]转16进制字符串(大写)
	hexStr := byteToHex(xByte)
	// 16进制字符串转byte[]
	strToByte := []byte(hexStr)

	n := 8 - len(strToByte)%8
	// 若str2Byte的位数不足8的倍数,需要在list前填充位数，第一位为n,第2至n-1位为0
	beforeEncryptList := make([]byte, len(strToByte)+n)
	for i := 0; i < len(strToByte)+n; i++ {
		if i == 0 {
			beforeEncryptList[i] = byte(n)
		} else if i < n {
			beforeEncryptList[i] = 0
		} else {
			beforeEncryptList[i] = strToByte[i-n]
		}
	}
	// TEA加密list
	var encryptList []int
	for i := 0; i < len(beforeEncryptList); i = i + 8 {
		tempInt := byteToInt(beforeEncryptList[i : i+8])
		tempEncrypt1, tempEncrypt2 := encryptByTea(tempInt, key, times)
		encryptList = append(encryptList, tempEncrypt1)
		encryptList = append(encryptList, tempEncrypt2)
	}
	// 列表转字节值的列表
	byteValue := intToByte(encryptList)
	// base64
	base64Str := base64.StdEncoding.EncodeToString(byteValue)
	// 把+号替换成%2B
	enTea = strings.Replace(base64Str, "+", "%2B", -1)
	return
}

func decryptByBase64Tea(message string) (deTea string) {
	// 把%2B替换成+号
	teaStr := strings.Replace(message, "%2B", "+", -1)
	// base64
	base64Bytes, base64Err := base64.StdEncoding.DecodeString(teaStr)
	if base64Err != nil {
		log.Println("base64Err = ", base64Err)
		return
	}
	// 字节数组转化成整型数组
	byte2Int := byteToInt(base64Bytes)
	// TEA解密
	var decryptList []int
	for i := 0; i < len(byte2Int); i = i + 2 {
		tempDecrypt1, tempDecrypt2 := decryptByTea(byte2Int[i:i+2], key, times)
		decryptList = append(decryptList, tempDecrypt1)
		decryptList = append(decryptList, tempDecrypt2)
	}
	byteValue := intToByte(decryptList)
	n := byteValue[0]
	// byte[]转16进制字符串
	hexStr := string(byteValue[n:len(byteValue)])
	tempBytes := hexToByte(hexStr)
	deTea = string(tempBytes)
	return
}

func main() {
	message := "XTea加密运算测试"
	enTea := encryptByBase64Tea(message)
	fmt.Println(enTea)
	deTea := decryptByBase64Tea(enTea)
	fmt.Println(deTea)
}
