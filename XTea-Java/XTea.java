package com.test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
/**
 * XTea算法
 * 每次操作可以处理8个字节数据
 * KEY为16字节,应为包含4个int型数的int[]，一个int为4个字节
 * 加密解密轮数应为8的倍数，推荐加密轮数为64轮
 *
 * @author : AIDAN
 * createTime : 2016-4-26
 */
public class XTea {

    /**
     * 加密解密所用的KEY
     */
    private final static int[] KEY = new int[]{
            0x789f5645, 0xf68bd5a4,
            0x81963ffa, 0xabcdef12
    };

    /**
     * 加密解密轮数（8的倍数）
     */
    private final static int TIMES = 32;

    /**
     * 算法给的标准值,不可以改
     */
    private final static int DELTA = 0x9e3779b9;

    /**
     * 加密[先GZIP压缩，再把字节数组转为16进制字符串，接着TEA加密，最后Base64编码]
     *
     * @param info 需加密内容
     * @return String
     */
    public static String encryptByBase64Tea(String info) {
        byte[] compressedBytes = info.getBytes(StandardCharsets.UTF_8);
        String hexStr = bytes2hex( compressedBytes );
        byte[] teaBytes = encryptByTea(  hexStr ) ;
        Base64.Encoder encoder = Base64.getEncoder();
        byte[] base64Bytes = encoder.encode(teaBytes);
        return replacePlus(new String(base64Bytes,StandardCharsets.UTF_8));
    }

    /**
     * 解密[先Base64解码，再TEA解密，接着把16进制字符串转为字节数组，最后解压]
     *
     * @param secretInfo 需解密内容
     * @return String
     */
    public static String decryptByBase64Tea( String secretInfo ){
        String info = addPlus(secretInfo);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decodeStr = decoder.decode(info);
        String teaStr = decryptByTea( decodeStr );
        byte[] hexBytes = hex2bytes(teaStr);
        String str = null;
        if(hexBytes.length > 0) {
            str = new String(hexBytes, StandardCharsets.UTF_8);
        }
        return str;
    }

    /**
     * 加密
     *
     * @param content 加密数据
     * @param offset 位移
     * @param key 加密解密KEY
     * @param times 加密解密轮数
     * @return byte[]
     */
    public static byte[] encrypt(byte[] content, int offset, int[] key, int times){
        int[] tempInt = byteToInt(content, offset);
        int y = tempInt[0], z = tempInt[1], sum = 0;
        while (times>0){
            sum += DELTA;
            y += ((z<<4) + key[0]) ^ (z + sum) ^ ((z>>5) + key[1]);
            z += ((y<<4) + key[2]) ^ (y + sum) ^ ((y>>5) + key[3]);
            times -= 1;
        }
        tempInt[0]=y;
        tempInt[1]=z;
        return intToByte(tempInt);
    }

    /**
     * 解密
     *
     * @param encryptContent 解密数据
     * @param offset 位移
     * @param key 加密解密KEY
     * @param times 加密解密轮数
     * @return byte[]
     */
    public static byte[] decrypt(byte[] encryptContent, int offset, int[] key, int times){
        int[] tempInt = byteToInt(encryptContent, offset);
        int y = tempInt[0], z = tempInt[1], sum ;
        if (times == 32) {
            // delta << 5
            sum = 0xC6EF3720;
        } else if (times == 16) {
            // delta << 4
            sum = 0xE3779B90;
        } else {
            sum = DELTA * times;
        }

        while (times>0){
            z -= ((y<<4) + key[2]) ^ (y + sum) ^ ((y>>5) + key[3]);
            y -= ((z<<4) + key[0]) ^ (z + sum) ^ ((z>>5) + key[1]);
            sum -= DELTA;
            times -= 1;
        }
        tempInt[0] = y;
        tempInt[1] = z;

        return intToByte(tempInt);
    }

    /**
     * byte[]型数据转成int[]型数据
     *
     * @param content 内容数据数组
     * @param offset 位移
     * @return int[]
     */
    private static int[] byteToInt(byte[] content, int offset){
        // 除以2的n次方 == 右移n位 即 content.length / 4 == content.length >> 2
        int[] result = new int[content.length >> 2];
        for(int i = 0, j = offset; j < content.length; i++, j += 4){
            result[i] = transform(content[j + 3]) | transform(content[j + 2]) << 8 |
                    transform(content[j + 1]) << 16 | (int)content[j] << 24;
        }
        return result;
    }

    /**
     * int[]型数据转成byte[]型数据
     *
     * @param content 内容数据数组
     * @return byte[]
     */
    private static byte[] intToByte(int[] content){
        // 乘以2的n次方 == 左移n位 即 content.length * 4 == content.length << 2
        byte[] result = new byte[content.length << 2];
        for(int i = 0, j = 0; j < result.length; i++, j += 4){
            result[j + 3] = (byte)(content[i] & 0xff);
            result[j + 2] = (byte)((content[i] >> 8) & 0xff);
            result[j + 1] = (byte)((content[i] >> 16) & 0xff);
            result[j] = (byte)((content[i] >> 24) & 0xff);
        }
        return result;
    }

    /**
     * 若某字节为负数则需将其转成无符号正数
     *
     * @param temp 字节
     * @return int
     */
    private static int transform(byte temp){
        int tempInt = temp;
        if(tempInt < 0){
            tempInt += 256;
        }
        return tempInt;
    }

    /**
     * 通过TEA算法加密信息
     *
     * @param info 需加密内容
     * @return byte[]
     */
    private static byte[] encryptByTea(String info){
        byte[] temp = info.getBytes();
        // 若temp的位数不足8的倍数,需要填充的位数
        int n = 8 - temp.length % 8;
        byte[] encryptStr = new byte[temp.length + n];
        encryptStr[0] = (byte)n;
        System.arraycopy(temp, 0, encryptStr, n, temp.length);
        byte[] result = new byte[encryptStr.length];
        for(int offset = 0; offset < result.length; offset += 8){
            byte[] tempEncrypt = encrypt(encryptStr, offset, KEY, TIMES);
            System.arraycopy(tempEncrypt, 0, result, offset, 8);
        }
        return result;
    }

    /**
     * 通过TEA算法解密信息
     *
     * @param secretInfo 加密信息字节数组
     * @return String
     */
    private static String decryptByTea(byte[] secretInfo){
        byte[] decryptStr = null;
        byte[] tempDecrypt = new byte[secretInfo.length];
        for(int offset = 0; offset < secretInfo.length; offset += 8){
            decryptStr = decrypt(secretInfo, offset, KEY, TIMES);
            System.arraycopy(decryptStr, 0, tempDecrypt, offset, 8);
        }
        int n = tempDecrypt[0];
        return new String(tempDecrypt, n, decryptStr.length - n);
    }

    /**
     * 把字节数组转为16进制字符串
     *
     * @param bytes 字节数组
     * @return String
     */
    private static String bytes2hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte aByte : bytes) {
            String temp = Integer.toHexString(aByte);
            if (temp.length() == 1) {
                temp = "0" + temp;
            } else {
                temp = temp.substring(temp.length() - 2);
            }
            sb.append(temp);
        }
        return sb.toString().toUpperCase(Locale.getDefault());

    }

    /**
     * 把16进制字符串转换为字节数组
     *
     * @param hex 16进制字符串
     * @return byte[]
     */
    private static byte[] hex2bytes(String hex) {
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        int len = hex.length() / 2;
        byte[] val = new byte[len];
        for (int i = 0; i < len; i++) {
            val[i] = (byte) (toInt(hex.charAt(2 * i)) * 16 + toInt(hex.charAt(2 * i + 1)));
        }
        return val;
    }

    /**
     * 把字符转为整形
     *
     * @param a 字符
     * @return int
     */
    private static int toInt(char a) {
        if (a >= '0' && a <= '9') {
            return a - '0';
        }
        if (a >= 'A' && a <= 'F') {
            return a - 55;
        }
        if (a >= 'a' && a <= 'f') {
            return a - 87;
        }
        return 0;
    }

    /**
     * 替换+号，方便网络传输
     *
     * @param paramTea 加密后的数据
     * @return String 完整的加密数据
     */
    private static String replacePlus(String paramTea){
        String teaStr = "";
        if(paramTea!=null && !"".equals(paramTea)){
            teaStr = paramTea.replace("+", "%2B");
        }
        return teaStr;
    }

    /**
     * 替换%2b
     *
     * @param paramTea 解密前的数据
     * @return String 完整的加密数据
     */
    private static String addPlus(String paramTea){
        String teaStr = "";
        if(paramTea!=null && !"".equals(paramTea)){
            teaStr = paramTea.replace("%2B", "+");
        }
        return teaStr;
    }

    public static void main(String[] args){
        String message = "XTea加密运算测试";
        String enTea = encryptByBase64Tea(message);
        System.out.println(enTea);
        String deTea = decryptByBase64Tea(enTea);
        System.out.println(deTea);
    }

}
