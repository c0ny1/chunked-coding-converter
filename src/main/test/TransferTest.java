import burp.Transfer;

public class TransferTest {
    public static void TestMergeReqBody(){
        byte[] byteBody = "1\r\na\r\n5\r\nab\r\nc\r\n3\r\nbbb0\n\n".getBytes();
        byte[] newBody = Transfer.mergeReqBody(byteBody);
        System.out.println(new String(newBody));
    }

    public static void TestSplitReqBody(){
        String reqbody = "{\n" +
                "    \"a\":1,\n" +
                "    \"b\":{\"c\":\"xxxx\"}\n" +
                "}";
        byte[] byteBody = reqbody.getBytes();
        byte[] newBody = Transfer.splitReqBody(byteBody,1,2,false,0,0);
        System.out.println(new String(newBody));
        System.out.println("---------------------");
        newBody = Transfer.mergeReqBody(newBody);
        System.out.println(new String(newBody));

    }

    public static void TestOk(){
        String body = "3;IWFbM4mTXBxSq7cjU2ZOrdg\r\n" +
                "ser\r\n" +
                "1;XcM0dC2gATfT2cMaX\r\n" +
                "v\r\n" +
                "1;HL3RZyqc2kk5E2ZRu0djQOu\r\n" +
                "i\r\n" +
                "3;AwPNeJDu\r\n" +
                "ce=\r\n" +
                "1;kvFfaa9\r\n" +
                "h\r\n" +
                "1;VwZXqUfdKcL\r\n" +
                "t\r\n" +
                "3;g0IdgC\r\n" +
                "tps\r\n" +
                "2;EHIqC5t\r\n" +
                "%3\r\n" +
                "3;6P49NW26kLv\r\n" +
                "A%2\r\n" +
                "1;Mg1IZGijv5keoWV3Pex\r\n" +
                "F\r\n" +
                "2;gYn0nPRoS5xfLEvE\r\n" +
                "%2\r\n" +
                "1;XqBYhlH0KbqUD1TKk\r\n" +
                "F\r\n" +
                "1;ToE8BVCsBm5VKj0C\r\n" +
                "y\r\n" +
                "2;2FLXZwRSXUAQ6ilT5pggbHUE\r\n" +
                "un\r\n" +
                "1;BZoEH3S3GqHU4Gqj0QxKj3\r\n" +
                ".\r\n" +
                "1;F5ddaFsfKx1MTjMEedJh\r\n" +
                "s\r\n" +
                "2;eqijFldn5Cga4tLA\r\n" +
                "cn\r\n" +
                "3;Vcb0BzTALRJKv6ji9duogGfwO\r\n" +
                "yw.\r\n" +
                "2;BVGq0Efdg\r\n" +
                "co\r\n" +
                "2;fvCiZ\r\n" +
                "m%\r\n" +
                "3;12ViYBzk3q67b\r\n" +
                "2Fp\r\n" +
                "1;Lb1uT4\r\n" +
                "o\r\n" +
                "1;brgH3py6bSqWI1qK\r\n" +
                "r\r\n" +
                "3;pNtzewGd2XM3lAH\r\n" +
                "tal\r\n" +
                "3;5NAfSvlZmv0D\r\n" +
                "%2F\r\n" +
                "0\n" +
                "\n";

        byte[] newBody = Transfer.mergeReqBody(body.getBytes());
        System.out.println(new String(newBody));

    }

    public static void main(String[] args) {
//        TestMergeReqBody();
//        TestSplitReqBody();
        TestOk();
    }
}


