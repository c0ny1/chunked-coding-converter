package burp;

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


    public static List<String> getStrList1(String str, int minLen, int maxLen){
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
}
