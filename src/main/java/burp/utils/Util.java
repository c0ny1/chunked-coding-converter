package burp.utils;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Util {
    /**
     * 把原始字符串分割成指定长度的字符串列表
     *
     * @param inputString 原始字符串
     * @param length 指定长度
     * @return
     */
    public static List<String> getStrList(String inputString, int length) {
        int size = inputString.length() / length;
        if (inputString.length() % length != 0) {
            size += 1;
        }
        return getStrList(inputString, length, size);
    }


    /**
     * 把原始字符串分割成指定长度的字符串列表
     *
     * @param inputString 原始字符串
     * @param length 指定长度
     * @param size 指定列表大小
     * @return
     */
    public static List<String> getStrList(String inputString, int length, int size) {
        List<String> list = new ArrayList<String>();
        for (int index = 0; index < size; index++) {
            String childStr = substring(inputString, index * length,(index + 1) * length);
            list.add(childStr);
        }
        return list;
    }

    /**
     * 把原始字符串分割成指定范围的随着长度字符串列表
     * @param str 要分割的字符串
     * @param minLen 随机最小长度
     * @param maxLen 随机最大长度
     * @return
     */
    public static List<String> getStrRandomLenList(String str, int minLen, int maxLen){
        List<String> list_str = new ArrayList<String>();
        int sum = 0;
        while (sum<str.length()){
            int l = getRandomNum(minLen,maxLen);
            list_str.add(substring(str,sum, sum+l));
            System.out.println(l);
            sum += l;
        }
        return list_str;
    }


    public static List<byte[]> getByteRandomLenList(byte[] data, int minLen, int maxLen){
        List<byte[]> list_str = new ArrayList<byte[]>();
        int sum = 0;
        while (sum < data.length){
            int l = getRandomNum(minLen,maxLen);
            if(sum + l > data.length){
                l = data.length - sum;
            }
            byte[] byteBody = new byte[l];
            System.arraycopy(data, sum, byteBody, 0, byteBody.length);
            list_str.add(byteBody);
            sum += l;
        }
        return list_str;
    }


    /**
     * 分割字符串，如果开始位置大于字符串长度，返回空
     *
     * @param str 原始字符串
     * @param f 开始位置
     * @param t 结束位置
     * @return
     */
    public static String substring(String str, int f, int t) {
        if (f > str.length())
            return null;
        if (t > str.length()) {
            return str.substring(f, str.length());
        } else {
            return str.substring(f, t);
        }
    }


    /**
     * 获取随机字符串
     * @param length
     * @return
     */
    public static String getRandomString(int length) {
        String str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
        Random random = new Random();
        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = str.charAt(random.nextInt(str.length()));
        }
        return new String(text);
    }

    /**
     * 获取min到max范围的随机数
     * @param min 最小数
     * @param max 最大数
     * @return 在min到max之间的一个随机数
     */
    public static Integer getRandomNum(int min,int max) {
        Random random = new Random();
        int num = random.nextInt(max) % (max - min + 1) + min;
        return num;
    }

    /**
     * 将10进制转换为16进制
     * @param decimal 10进制
     * @return 16进制
     */
    public static String decimalToHex(int decimal) {
        String hex = Integer.toHexString(decimal);
        return  hex.toUpperCase();
    }

    /**
     * 将16进制转10进制
     * @param hex
     * @return
     */
    public static int hexToDecimal(String hex){
        BigInteger bigInteger = new BigInteger(hex,16);
        return bigInteger.intValue();
    }


    /**
     * 判断数据中是否包含不可见字符
     * @param data 要判断的数据
     * @return 是否包含不可见字符
     */
    public static boolean isIncludeInviChar(byte[] data){
        for(int i=0;i<data.length;i++){
            int value = Integer.valueOf(data[i]);

            if(value < 0 || value > 127){
                return true;
            }
        }

        return false;
    }


    public static String getUrlFormIReqRsp(IHttpRequestResponse iHttpRequestResponse){
        IHttpService httpService = iHttpRequestResponse.getHttpService();
        byte[] request = iHttpRequestResponse.getRequest();
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(httpService,request);
        String url = requestInfo.getUrl().toString();
        return url;
    }

    public static int getReqBodyLenFormIReqRsp(IHttpRequestResponse iHttpRequestResponse){
        byte[] request = iHttpRequestResponse.getRequest();
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        return body_length;
    }


    public static int getRandom(int min,int max) throws Exception {
        if(max<min){
            throw new Exception("max must be > min");
        }
        int random = (int) (Math.random()*(max-min)+min);
        return random;
    }


    public static String getThrowableInfo(Throwable throwable){
        StringWriter writer = new StringWriter();
        PrintWriter printWriter = new PrintWriter(writer);
        throwable.printStackTrace(printWriter);
        return writer.toString();
    }

    public static boolean bytesEndWith(byte[] bytes, byte[] end){
        int endLen = end.length;
        int bytesLen = bytes.length;

        for(int i=1;i<end.length;i++){
            if(end[endLen - i] != bytes[bytesLen - i]){
                return false;
            }
        }
        return true;
    }
}
