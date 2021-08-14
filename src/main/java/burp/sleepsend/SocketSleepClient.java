package burp.sleepsend;

import burp.BurpExtender;
import burp.Transfer;
import burp.utils.DateUtil;
import burp.utils.Util;

import javax.net.ssl.*;
import javax.swing.*;
import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// https://www.iteye.com/problems/42407
public class SocketSleepClient {
    private SleepSendConfig sleepSendConfig;
    private ExecutorService executorService  = Executors.newSingleThreadExecutor();
    private String url;
    private String host;
    private int port;
    private boolean isSSL;
    private LinkedHashMap<String,String> headers = new LinkedHashMap<String, String>();
    private byte[] reqBody;
    private int totalLen; // 要分块内容的总长度
    private int sentedLen; // 已经发送数据的长度

    public SocketSleepClient(String url, LinkedHashMap<String,String> headers, byte[] reqBody,SleepSendConfig config) throws MalformedURLException {
        this.url = url;
        if(url.startsWith("https://")){
            isSSL = true;
        }else{
            isSSL = false;
        }
        URL u = new URL(this.url);
        this.host = u.getHost();

        if(u.getPort() != -1){
            this.port = u.getPort();
        }else if(isSSL){
            this.port = 443;
        }else{
            this.port = 80;
        }

        this.headers = headers;
        this.headers.put("Transfer-Encoding","chunked");
        this.headers.remove("Content-Length");
        this.headers.remove("Connection");
        this.headers.put("Connection","keep-alive");
        this.reqBody = reqBody;
        this.totalLen = reqBody.length;
        this.sleepSendConfig = config;
    }


    public byte[] send() throws Exception{
        this.sentedLen = 0;
        JProgressBar pgBar = sleepSendConfig.getPgBar();
        pgBar.setValue(sentedLen);
        // connect
        Socket socket = null;
        if(sleepSendConfig.isEnableSocks5Proxy()){
            SocketAddress addr = new InetSocketAddress(sleepSendConfig.getProxyHost(), sleepSendConfig.getProxyPort());
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);
            socket = new Socket(proxy);
        }else{
            socket = new Socket();
        }

        InetSocketAddress address = new InetSocketAddress(host, port);
        try {
            if (isSSL) {
                X509TrustManagerImpl x509m = new X509TrustManagerImpl();
                // 获取一个SSLContext实例
                SSLContext sslContext = SSLContext.getInstance("SSL");
                // 初始化SSLContext实例
                sslContext.init(null, new TrustManager[]{x509m}, new java.security.SecureRandom());
                socket.connect(address);
                socket = sslContext.getSocketFactory().createSocket(socket, address.getHostName(), address.getPort(), true);
            } else {
                socket.connect(address);
            }
        }catch (Throwable e){
            String msg = Util.getThrowableInfo(e);
            ChunkedInfoEntity chunkedInfoEntity = new ChunkedInfoEntity();
            chunkedInfoEntity.setId(-1);
            chunkedInfoEntity.setChunkedContent("-".getBytes());
            chunkedInfoEntity.setChunkedLen(0);
            chunkedInfoEntity.setSleepTime(0);
            chunkedInfoEntity.setStatus("Connect error: " + msg);
            printLog(chunkedInfoEntity);
            return msg.getBytes();
        }


        OutputStream osw = socket.getOutputStream();
        // send request header
        try {
            osw.write(String.format("%s\r\n", headers.get("top")).getBytes());
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (header.getKey().contains("top")) {
                    continue;
                }
                osw.write(String.format("%s: %s\r\n", header.getKey(), header.getValue()).getBytes());
            }
            osw.write("\r\n".getBytes());
            osw.flush();
        }catch (Throwable e){
            String msg = Util.getThrowableInfo(e);
            ChunkedInfoEntity chunkedInfoEntity = new ChunkedInfoEntity();
            chunkedInfoEntity.setId(0);
            chunkedInfoEntity.setChunkedContent("-".getBytes());
            chunkedInfoEntity.setChunkedLen(0);
            chunkedInfoEntity.setSleepTime(0);
            chunkedInfoEntity.setStatus("send request header error: " + msg);
            printLog(chunkedInfoEntity);
            return msg.getBytes();
        }

        // send request body
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(reqBody);
        byte[] buffer = new byte[calcRandomChunkedLen()];
        int id = 1;
        boolean isError = false;
        String errorMsg = "";
        final String startTime = DateUtil.getNowTime();
        while (byteArrayInputStream.read(buffer) != -1){
            final ChunkedInfoEntity chunkeInfoEntity = new ChunkedInfoEntity();
            chunkeInfoEntity.setId(id);
            try {
                // 发送分块长度
                final String chunkedLen = Util.decimalToHex(buffer.length) + "\r\n";
                osw.write(chunkedLen.getBytes());
                chunkeInfoEntity.setChunkedLen(buffer.length);
                osw.flush();

                // 发送分块内容
                byte[] chunked = Transfer.joinByteArray(buffer, "\r\n".getBytes());
                BurpExtender.stdout.println(new String(chunked));
                chunkeInfoEntity.setChunkedContent(buffer);
                osw.write(chunked);
                osw.flush();
                chunkeInfoEntity.setStatus("ok");
                this.sentedLen += buffer.length;
                pgBar.setValue(this.sentedLen);
                // 延时
                int sleeptime = Util.getRandom(sleepSendConfig.getMinSleepTime(), sleepSendConfig.getMaxSleepTime());
                chunkeInfoEntity.setSleepTime(sleeptime);
                Thread.sleep(sleeptime);
            }catch (Throwable throwable){
                chunkeInfoEntity.setStatus("fail " + throwable.getMessage());
                isError = true;
                errorMsg = Util.getThrowableInfo(throwable);
            }

            printLog(chunkeInfoEntity);

            double time = DateUtil.betweenMs(startTime, DateUtil.getNowTime());
            sleepSendConfig.getLbTotalTime().setText(DateUtil.ms2str(time));

            buffer = new byte[calcRandomChunkedLen()];
            sleepSendConfig.getLbTotalChunked().setText(String.valueOf(id));
            id ++;

            if(isError){
                break;
            }
        }

        if(!isError) {
            osw.write("0\r\n\r\n".getBytes());
            osw.flush();
            pgBar.setValue(totalLen);
            sleepSendConfig.getResponseViewer().setMessage("Reading Response, please wait...".getBytes(),false);
            byte[] result = readFullHttpResponse(socket.getInputStream());
            pgBar.setValue(totalLen + 1);
            if(result.length == 0){
                return "read response is null".getBytes();
            }else{
                return result;
            }
        }else{
            return errorMsg.getBytes();
        }
    }


    public int calcRandomChunkedLen() throws Exception {
        int randomLen = Util.getRandom(sleepSendConfig.getMinChunkedLen(),sleepSendConfig.getMaxChunkedLen());
        if(this.sentedLen + randomLen > this.totalLen){
            randomLen = this.totalLen - this.sentedLen;
        }
        return randomLen;
    }


    public void printLog(final ChunkedInfoEntity chunkeInfoEntity){
        executorService.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    List<ChunkedInfoEntity> chunkedInfos = sleepSendConfig.getChunkedLogTable().getChunkedLogModel().getChunkedInfos();
                    synchronized (chunkedInfos) {
                        int row = chunkedInfos.size();
                        chunkedInfos.add(chunkeInfoEntity);
                        sleepSendConfig.getChunkedLogTable().getChunkedLogModel().fireTableRowsInserted(row, row);
                    }
                }catch (Throwable throwable){
                    throwable.printStackTrace(BurpExtender.stderr);
                }
            }
        });
    }


    public static byte[] readFullHttpResponse(InputStream inputStream) throws IOException, InterruptedException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1];
        boolean isChunked = false; //是否是分块回传
        int contentLength = 0;
        int acceptedLength = 0;
        boolean proccessedHeader = false; //是否处理过header

        while (true){
            int flag = inputStream.read(buffer);
            outputStream.write(buffer);
            byte[] readedContent = outputStream.toByteArray();
            if(!proccessedHeader && Util.bytesEndWith(readedContent,"\r\n\r\n".getBytes())){
                Map headers = new HashMap<String,String>();
                String responseHeader = new String(readedContent);
                for(String header:responseHeader.split("\r\n")){
                    if(header.contains(":")){
                        String reqHeaderKey = header.substring(0,header.indexOf(":")).trim();
                        String reqHeaderValue = header.substring(header.indexOf(":")+1,header.length()).trim();
                        headers.put(reqHeaderKey,reqHeaderValue);
                    }
                }

                if(headers.containsKey("Content-Length")){
                    contentLength = Integer.valueOf((String)headers.get("Content-Length"));
                }else if(headers.containsKey("Transfer-Encoding") && headers.get("Transfer-Encoding").equals("chunked")){
                    isChunked = true;
                }
                proccessedHeader = true;
            }

            if(isChunked){
                if(Util.bytesEndWith(readedContent,"\r\n0\r\n\r\n".getBytes())) {
                    break;
                }
            }else if(contentLength != 0){
                if(acceptedLength == contentLength){
                    break;
                }
                acceptedLength ++;
            }else if(flag == -1){
                break;
            }
        }
        return outputStream.toByteArray();
    }
}
