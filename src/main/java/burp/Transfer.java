package burp;

import java.io.UnsupportedEncodingException;
import java.util.*;

/**
 * 编码解码类，负责对目标请求进行编码解码
 */
public class Transfer {
    /**
     * 对请求包进行chunked编码
     * @param requestResponse 要处理的请求响应对象
     * @param minChunkedLen 分块最短长度
     * @param maxChunkedLen 分块最长长度
     * @param isComment 是否添加注释
     * @param minCommentLen 注释最短长度
     * @param maxCommentLen 注释最长长度
     * @return 编码后的请求包
     * @throws UnsupportedEncodingException
     */
    public static  byte[] encoding(IHttpRequestResponse requestResponse,int minChunkedLen, int maxChunkedLen, boolean isComment,int minCommentLen,int maxCommentLen) throws UnsupportedEncodingException {
        byte[] request = requestResponse.getRequest();
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        String body = new String(request, bodyOffset, body_length, "UTF-8");

        if (request.length - bodyOffset > 10000){
            return request;
        }

        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            //不对请求包重复编码
            if (((String)iter.next()).contains("Transfer-Encoding")) {
                return request;
            }
        }
        //Add Transfer-Encoding header
        headers.add("Transfer-Encoding: chunked");

        //encoding
        List<String> str_list = Util.getStrRandomLenList(body,minChunkedLen,maxChunkedLen);
        String encoding_body = "";
        for(String str:str_list){
            if(isComment){
                int commentLen = Util.getRandomNum(minCommentLen,maxCommentLen);
                encoding_body += String.format("%s;%s",Util.decimalToHex(str.length()),Util.getRandomString(commentLen));
            }else{
                encoding_body += Util.decimalToHex(str.length());
            }
            encoding_body += "\r\n";
            encoding_body += str;
            encoding_body += "\r\n";
        }
        encoding_body += "0\r\n\r\n";



        return BurpExtender.helpers.buildHttpMessage(headers,encoding_body.getBytes());
    }


    /**
     * 对编码过的请求包进行解码
     * @param requestResponse 已编码过的请求响应对象
     * @return 解码后的请求包
     * @throws UnsupportedEncodingException
     */
    public static byte[] decoding(IHttpRequestResponse requestResponse) throws UnsupportedEncodingException {
        byte[] request = requestResponse.getRequest();
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        String body = new String(request, bodyOffset, request.length - bodyOffset, "UTF-8");

        // Delete Transfer-Encoding header
        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        Iterator<String> iter = headers.iterator();
        Boolean isChunked = false;//是否被分块编码过
        while (iter.hasNext()) {
            if (((String)iter.next()).contains("Transfer-Encoding")) {
                iter.remove();
                isChunked = true;
            }
        }
        //不对未编码过的请求包解码
        if(!isChunked){
            return request;
        }

        //Decoding
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

        return BurpExtender.helpers.buildHttpMessage(headers,decoding_body.getBytes());
    }


    /**
     * 通过数据包头部是否存在Transfer-Encoding头，来判断其是否被编码
     * @param requestResponse
     * @return 是否被编码
     */
    public static boolean isChunked(IHttpRequestResponse requestResponse){
        byte[] request = requestResponse.getRequest();
        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            if (((String)iter.next()).contains("Transfer-Encoding")) {
                return true;
            }
        }
        return false;
    }
}
