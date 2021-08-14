package burp.sleepclient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

import static burp.sleepclient.SocketSleepClient.readFullHttpResponse;

public class SocketSleepClientTest {


    @org.junit.Test
    public void send() throws Exception {
        X509TrustManagerImpl x509m = new X509TrustManagerImpl();
        // 获取一个SSLContext实例
        SSLContext sslContext = SSLContext.getInstance("SSL");
        // 初始化SSLContext实例
        sslContext.init(null, new TrustManager[] { x509m }, new java.security.SecureRandom());

        String prxyhost = "127.0.0.1";
        int prxyport = 1188;
        SocketAddress addr = new InetSocketAddress(prxyhost, Integer.valueOf(prxyport));
        Proxy proxy = new Proxy(Proxy.Type.SOCKS, addr);
        Socket socket = new Socket(proxy);

        InetSocketAddress address = new InetSocketAddress("2021.ip138.com", 443);
        socket.connect(address);

        Socket sslSocket = sslContext.getSocketFactory().createSocket(socket,address.getHostName(), address.getPort(), true);

        //sslSocket.connect(new InetSocketAddress("www.baidu.com",443));
        OutputStream osw = sslSocket.getOutputStream();
        osw.write("GET / HTTP/1.1\r\n".getBytes());
        osw.write("Host: 2021.ip138.com\r\n".getBytes());
        osw.write("Connection: close\r\n\r\n".getBytes());
        osw.flush();

        byte[] result = readFullHttpResponse(sslSocket.getInputStream());
        System.out.println(new String(result));
    }



    public static void sendUrl() throws IOException {
        byte[] test = "abcdefq".getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(test);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1];
        while (inputStream.read(buffer) != -1){
            byteArrayOutputStream.write(buffer);
            System.out.println(new String(byteArrayOutputStream.toByteArray()));
        }
    }




    public static void main(String[] args) throws IOException {
        sendUrl();
    }


}