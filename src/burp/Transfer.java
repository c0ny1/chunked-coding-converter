package burp;

import java.io.UnsupportedEncodingException;
import java.util.*;

public class Transfer {
    public static  byte[] encoding(IExtensionHelpers helpers, IHttpRequestResponse requestResponse, int split_len, boolean isComment) throws UnsupportedEncodingException {
        byte[] request = requestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        String body = new String(request, bodyOffset, body_length, "UTF-8");

        if (request.length - bodyOffset > 10000){
            return request;
        }

        List<String> str_list = Util.getStrList(body,Config.splite_len);
        String encoding_body = "";
        for(String str:str_list){
            if(Config.isComment){
                encoding_body += String.format("%s;%s",Util.decimalToHex(str.length()),Util.getRandomString(10));
            }else{
                encoding_body += Util.decimalToHex(str.length());
            }
            encoding_body += "\r\n";
            encoding_body += str;
            encoding_body += "\r\n";
        }
        encoding_body += "0\r\n\r\n";

        List<String> headers = helpers.analyzeRequest(request).getHeaders();

        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            if (((String)iter.next()).contains("Transfer-Encoding")) {
                iter.remove();
            }
        }
        headers.add("Transfer-Encoding: chunked");
        return helpers.buildHttpMessage(headers,encoding_body.getBytes());
    }

    public static byte[] decoding(IExtensionHelpers helpers, IHttpRequestResponse requestResponse) throws UnsupportedEncodingException {
        byte[] request = requestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        String body = new String(request, bodyOffset, request.length - bodyOffset, "UTF-8");

        // decoding
        String[] array_body = body.split("\r\n");
        List<String> list_string_body = Arrays.asList(array_body);
        List list_body = new ArrayList(list_string_body);
        list_body.remove(list_body.size()-1);
        String decoding_body = "";
        for(int i=0;i<list_body.size();i++){
            int n = i%2;
            if(n != 0){
                decoding_body += list_body.get(i);
            }
        }

        // del Transfer-Encoding header
        List<String> headers = helpers.analyzeRequest(request).getHeaders();
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            if (((String)iter.next()).contains("Transfer-Encoding")) {
                iter.remove();
            }
        }

        return helpers.buildHttpMessage(headers,decoding_body.getBytes());
    }
}
