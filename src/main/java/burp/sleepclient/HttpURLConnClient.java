package burp.sleepclient;

import burp.BurpExtender;
import burp.Transfer;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpURLConnClient {
    private String url;
    private boolean isSSL;
    private Map<String,String> headers = new HashMap<String, String>();
    private byte[] reqBody;
    private  int chunkedLen = 5;
    private int minSleepTime = 1000;
    private int maxSleepTime = 3000;

    public HttpURLConnClient(String url,Map<String,String> headers,byte[] reqBody){
        this.url = url;
        if(url.endsWith("https://")){
            isSSL = true;
        }else{
            isSSL = false;
        }
        this.headers = headers;
        this.reqBody = reqBody;
    }

    public void setChunkedLen(int chunkedLen) {
        this.chunkedLen = chunkedLen;
    }

    public void setMinSleepTime(int minSleepTime) {
        this.minSleepTime = minSleepTime;
    }

    public void setMaxSleepTime(int maxSleepTime) {
        this.maxSleepTime = maxSleepTime;
    }

    public byte[] send(){
        OutputStream out = null;
        BufferedReader in = null;
        byte[] response = new byte[0];
        try {
            URL realUrl = new URL(url);
            // 打开和URL之间的连接
            HttpURLConnection conn = (HttpURLConnection)realUrl.openConnection();

            conn.setChunkedStreamingMode(chunkedLen);
            // 设置通用的请求属性
            for(Map.Entry<String,String> header:headers.entrySet()){
                conn.setRequestProperty(header.getKey(),header.getValue());
            }

            // 发送POST请求必须设置如下两行
            conn.setDoOutput(true);
            conn.setDoInput(true);

            // 获取URLConnection对象对应的输出流
            out = conn.getOutputStream();
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(reqBody);
            byte[] buffer = new byte[chunkedLen];
            while (byteArrayInputStream.read(buffer)!= -1){
                out.write(buffer);
                out.flush();

                BurpExtender.stdout.println(String.format("[+] send %d finish!",buffer.length));
                int sleeptime = getRandom(minSleepTime,maxSleepTime);
                Thread.sleep(sleeptime);
                BurpExtender.stdout.println(String.format("[*] sleep %d finish!",sleeptime));
            }
            out.flush();

            // 定义BufferedReader输入流来读取URL的响应
            String rspHeader = "";
            Map<String, List<String>> mapHeaders = conn.getHeaderFields();
            for (Map.Entry<String, List<String>> entry : mapHeaders.entrySet()) {
                String key = entry.getKey();
                List<String> values = entry.getValue();
                String value = "";
                for(String v:values){
                    value += v;
                }

                if(key == null) {
                    String header_line = String.format("%s\r\n",value);
                    rspHeader += header_line;
                }else{
                    String header_line = String.format("%s: %s\r\n", key, value);
                    rspHeader += header_line;
                }
            }

            byte[] result = readInputStream(conn.getInputStream());
            response = Transfer.joinByteArray(rspHeader.getBytes(),"\r\n".getBytes());
            response = Transfer.joinByteArray(response,result);
        } catch (Exception e) {
            e.printStackTrace(BurpExtender.stderr);
        } finally{
            try{
                if(out!=null){
                    out.close();
                }
                if(in!=null){
                    in.close();
                } }
            catch(IOException ex){
                ex.printStackTrace();
            }
        }
        return response;
    }



    public static byte[] readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (inputStream.read(buffer) != -1){
            byteArrayOutputStream.write(buffer);
        }

        return byteArrayOutputStream.toByteArray();
    }

    public static int getRandom(int min,int max) throws Exception {
        if(max<min){
            throw new Exception("max must be > min");
        }
        int random = (int) (Math.random()*(max-min)+min);
        return random;
    }
}
