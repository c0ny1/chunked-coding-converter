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

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        byte[] byteBody = new byte[body_length];
        System.arraycopy(request, bodyOffset, byteBody, 0, body_length);

        byte[] byte_encoding_body = splitReqBody(byteBody,minChunkedLen,maxChunkedLen,isComment,minCommentLen,maxCommentLen);
        return BurpExtender.helpers.buildHttpMessage(headers,byte_encoding_body);
    }


    public static byte[] joinByteArray(byte[] byte1, byte[] byte2) {
            byte[] bt3 = new byte[byte1.length+byte2.length];
            System.arraycopy(byte1, 0, bt3, 0, byte1.length);
            System.arraycopy(byte2, 0, bt3, byte1.length, byte2.length);
            return bt3;
    }

    /**
     * 对编码过的请求包进行解码
     * @param requestResponse 已编码过的请求响应对象
     * @return 解码后的请求包
     * @throws UnsupportedEncodingException
     */
    public static byte[] decoding(IHttpRequestResponse requestResponse)  {
        byte[] request = requestResponse.getRequest();

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

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        byte[] byteBody = new byte[body_length];
        System.arraycopy(request, bodyOffset, byteBody, 0, body_length);
        byte[] mergeReqBody = mergeReqBody(byteBody);

        return BurpExtender.helpers.buildHttpMessage(headers,mergeReqBody);
    }


    /**
     * 将request body分块
     * @param reqBody
     * @param minChunkedLen
     * @param maxChunkedLen
     * @param isComment
     * @param minCommentLen
     * @param maxCommentLen
     * @return
     */
    public static byte[] splitReqBody(byte[] reqBody,int minChunkedLen,int maxChunkedLen,boolean isComment,int minCommentLen,int maxCommentLen){
        List<byte[]> bytes_list = Util.getByteRandomLenList(reqBody,minChunkedLen,maxChunkedLen);
        byte[] byte_encoding_body = new byte[0];
        for(byte[] b:bytes_list){
            // 当注释开启，同时不存在不可见字符时，才会添加注释
            if(isComment && !Util.isIncludeInviChar(reqBody)){
                int commentLen = Util.getRandomNum(minCommentLen,maxCommentLen);
                String comment = String.format("%s;%s",Util.decimalToHex(b.length),Util.getRandomString(commentLen));
                byte_encoding_body = joinByteArray(byte_encoding_body,comment.getBytes());
            }else{
                byte_encoding_body = joinByteArray(byte_encoding_body,Util.decimalToHex(b.length).getBytes());
            }
            byte_encoding_body = joinByteArray(byte_encoding_body,"\r\n".getBytes());
            byte_encoding_body = joinByteArray(byte_encoding_body,b);
            byte_encoding_body = joinByteArray(byte_encoding_body,"\r\n".getBytes());
        }
        byte_encoding_body = joinByteArray(byte_encoding_body,"0\n\n".getBytes());
        return byte_encoding_body;
    }


    /**
     * 将分块的req body合并
     * @param chunkedReqBody
     * @return
     */
    public static byte[] mergeReqBody(byte[] chunkedReqBody){
        byte[] mergeBody = new byte[0];
        int j = 0;

        for(int i = 0;i < chunkedReqBody.length; i++){
            if(i+1 <= chunkedReqBody.length
                    && chunkedReqBody[i] == "\r".getBytes()[0]
                    && chunkedReqBody[i+1] == "\n".getBytes()[0]){

                // 获取分块长度
                int length = i - j;
                byte[] chunkedLen = new byte[length];
                System.arraycopy(chunkedReqBody, j, chunkedLen, 0, length);
                j = i + 2;
                int cLen = Util.hexToDecimal(new String(chunkedLen));
                // 根据分块长度获取分块内容
                byte[] chunked = new byte[cLen];
                System.arraycopy(chunkedReqBody, j, chunked, 0, cLen);
                mergeBody = joinByteArray(mergeBody,chunked);
                j = j + cLen + 2;
                i = j;
                continue;
            }

            // 处理结尾0\n\n
            if(chunkedReqBody[i] == "0".getBytes()[0]
                    && chunkedReqBody[i+1] == "\n".getBytes()[0]
                    && chunkedReqBody[i+2] == "\n".getBytes()[0]){
                break;
            }
        }
        return mergeBody;
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
