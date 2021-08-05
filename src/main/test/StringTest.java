import burp.Util;

public class StringTest {
    public static void main(String[] args) {
        String data = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&\\'()*+,-./:;<=>?@[\\\\]^_`{|}~ \\t\\n";
        data = "\r\n";
        System.out.println(Util.isIncludeInviChar(data.getBytes()));
    }
}
