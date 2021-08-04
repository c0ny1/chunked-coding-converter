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

    public static void main(String[] args) {
        TestMergeReqBody();
        TestSplitReqBody();
    }
}


