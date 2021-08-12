package burp.sleepclient;

import burp.BurpExtender;
import burp.Transfer;
import burp.utils.DateUtil;
import burp.utils.Util;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
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

    public SocketSleepClient(String url, LinkedHashMap<String,String> headers, byte[] reqBody,SleepSendConfig config) throws MalformedURLException {
        this.url = url;
        if(url.endsWith("https://")){
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

        this.sleepSendConfig = config;
        if(sleepSendConfig.isEnableSocks5Proxy()) {

        }
    }


    public byte[] send() throws Exception{

        Socket socket = null;
        if(sleepSendConfig.isEnableSocks5Proxy()){
            SocketAddress addr = new InetSocketAddress(sleepSendConfig.getProxyHost(), sleepSendConfig.getProxyPort());
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);
            socket = new Socket(proxy);
        }else{
            socket = new Socket();
        }

        InetSocketAddress address = new InetSocketAddress(host, port);
        if(isSSL){
            X509TrustManagerImpl x509m = new X509TrustManagerImpl();
            // 获取一个SSLContext实例
            SSLContext sslContext = SSLContext.getInstance("SSL");
            // 初始化SSLContext实例
            sslContext.init(null, new TrustManager[] { x509m }, new java.security.SecureRandom());

            socket.connect(address);
            socket = sslContext.getSocketFactory().createSocket(socket,address.getHostName(), address.getPort(), true);
        }else{
            socket.connect(address);
        }


        //sslSocket.connect(new InetSocketAddress("www.baidu.com",443));
        OutputStream osw = socket.getOutputStream();
        osw.write(String.format("%s\r\n",headers.get("top")).getBytes());
        for(Map.Entry<String,String> header:headers.entrySet()){
            if(header.getKey().contains("top")){
                continue;
            }
            osw.write(String.format("%s: %s\r\n",header.getKey(),header.getValue()).getBytes());
        }
        osw.write("\r\n".getBytes());
        osw.flush();

//        osw.write("GET / HTTP/1.1\r\n".getBytes());
//        osw.write("Host: 2021.ip138.com\r\n".getBytes());
//        osw.write("Connection: close\r\n\r\n".getBytes());
//        osw.flush();

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(reqBody);
        byte[] buffer = new byte[getRandom(sleepSendConfig.getMinChunkedLen(),sleepSendConfig.getMaxChunkedLen())];
        int id = 1;
        boolean isError = false;
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
                int sleeptime = getRandom(sleepSendConfig.getMinSleepTime(), sleepSendConfig.getMaxSleepTime());
                chunkeInfoEntity.setSleepTime(sleeptime);
                byte[] chunked = Transfer.joinByteArray(buffer, "\r\n".getBytes());
                BurpExtender.stdout.println(new String(chunked));
                chunkeInfoEntity.setChunkedContent(buffer);
                osw.write(chunked);
                osw.flush();
                chunkeInfoEntity.setStatus("ok");
                // 延时
                Thread.sleep(sleeptime);
            }catch (Throwable throwable){
                chunkeInfoEntity.setStatus("fail " + throwable.getMessage());
                isError = true;
            }

            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    List<ChunkedInfoEntity> chunkedInfos = sleepSendConfig.getChunkedLogTable().getModel().getChunkedInfos();
                    synchronized (chunkedInfos) {
                        double time = DateUtil.betweenMs(startTime, DateUtil.getNowTime());
                        sleepSendConfig.getLbTotalTime().setText(DateUtil.ms2str(time));
                        int row = chunkedInfos.size();
                        chunkedInfos.add(chunkeInfoEntity);
                        sleepSendConfig.getChunkedLogTable().getModel().fireTableRowsInserted(row, row);
                    }
                }
            });

            buffer = new byte[getRandom(sleepSendConfig.getMinChunkedLen(),sleepSendConfig.getMaxChunkedLen())];
            sleepSendConfig.getLbTotalChunked().setText(String.valueOf(id));
            id ++;

            if(isError){
                break;
            }
        }

        if(!isError) {
            osw.write("0\r\n\r\n".getBytes());
            osw.flush();

            byte[] result = readInputStream(socket.getInputStream());
            return result;
        }else{
            return new byte[0];
        }
    }


    public static int getRandom(int min,int max) throws Exception {
        if(max<min){
            throw new Exception("max must be > min");
        }
        int random = (int) (Math.random()*(max-min)+min);
        return random;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, KeyManagementException, InterruptedException {

//        X509TrustManagerImpl x509m = new X509TrustManagerImpl();
//        // 获取一个SSLContext实例
//        SSLContext sslContext = SSLContext.getInstance("SSL");
//        // 初始化SSLContext实例
//        sslContext.init(null, new TrustManager[] { x509m }, new java.security.SecureRandom());
//
//
//        String prxyhost = "127.0.0.1";
//        int prxyport = 1188;
//        SocketAddress addr = new InetSocketAddress(prxyhost, Integer.valueOf(prxyport));
//        Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);
//        Socket socket = new Socket(proxy);
//
//        InetSocketAddress address = new InetSocketAddress("2021.ip138.com", 443);
//        socket.connect(address);
//
//        Socket sslSocket = sslContext.getSocketFactory().createSocket(socket,address.getHostName(), address.getPort(), true);
//
//        //sslSocket.connect(new InetSocketAddress("www.baidu.com",443));
//
//
//
//        OutputStream osw = sslSocket.getOutputStream();
//        osw.write("GET / HTTP/1.1\r\n".getBytes());
//        osw.write("Host: 2021.ip138.com\r\n".getBytes());
//        osw.write("Connection: close\r\n\r\n".getBytes());
//        osw.flush();
//
//        byte[] result = readInputStream(sslSocket.getInputStream());
//
//        System.out.println(new String(result));

        URL x = new URL("http://www.baidu.com");
        System.out.println(x.getPort());

    }



    public static byte[] readInputStream(InputStream inputStream) throws IOException, InterruptedException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (inputStream.read(buffer) != -1){
            byteArrayOutputStream.write(buffer);
            Thread.sleep(800);
        }

        return byteArrayOutputStream.toByteArray();
    }
}
