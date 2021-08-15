package burp.sleepchunked;

import burp.ChunkedLogTable;
import burp.IMessageEditor;

import javax.swing.*;

public class SleepSendConfig {
    private int minChunkedLen;
    private int maxChunkedLen;
    private int minSleepTime;
    private int maxSleepTime;
    private boolean enableSocks5Proxy;
    private String proxyHost;
    private int proxyPort;
    private JLabel lbTotalChunked;
    private JLabel lbTotalTime;
    private ChunkedLogTable chunkedLogTable;
    private JProgressBar pgBar;
    private IMessageEditor responseViewer;
    private JButton btnSend;

    public int getMinChunkedLen() {
        return minChunkedLen;
    }

    public void setMinChunkedLen(int minChunkedLen) {
        this.minChunkedLen = minChunkedLen;
    }

    public int getMaxChunkedLen() {
        return maxChunkedLen;
    }

    public void setMaxChunkedLen(int maxChunkedLen) {
        this.maxChunkedLen = maxChunkedLen;
    }

    public int getMinSleepTime() {
        return minSleepTime;
    }

    public void setMinSleepTime(int minSleepTime) {
        this.minSleepTime = minSleepTime;
    }

    public int getMaxSleepTime() {
        return maxSleepTime;
    }

    public void setMaxSleepTime(int maxSleepTime) {
        this.maxSleepTime = maxSleepTime;
    }

    public boolean isEnableSocks5Proxy() {
        return enableSocks5Proxy;
    }

    public void setEnableSocks5Proxy(boolean enableSocks5Proxy) {
        this.enableSocks5Proxy = enableSocks5Proxy;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public void setProxyHost(String proxyHost) {
        this.proxyHost = proxyHost;
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(int proxyPort) {
        this.proxyPort = proxyPort;
    }

    public JLabel getLbTotalChunked() {
        return lbTotalChunked;
    }

    public void setLbTotalChunked(JLabel lbTotalChunked) {
        this.lbTotalChunked = lbTotalChunked;
    }

    public JLabel getLbTotalTime() {
        return lbTotalTime;
    }

    public void setLbTotalTime(JLabel lbTotalTime) {
        this.lbTotalTime = lbTotalTime;
    }

    public ChunkedLogTable getChunkedLogTable() {
        return chunkedLogTable;
    }

    public void setChunkedLogTable(ChunkedLogTable chunkedLogTable) {
        this.chunkedLogTable = chunkedLogTable;
    }

    public IMessageEditor getResponseViewer() {
        return responseViewer;
    }

    public void setResponseViewer(IMessageEditor responseViewer) {
        this.responseViewer = responseViewer;
    }

    public JProgressBar getPgBar() {
        return pgBar;
    }

    public void setPgBar(JProgressBar pgBar) {
        this.pgBar = pgBar;
    }

    public JButton getBtnSend() {
        return btnSend;
    }

    public void setBtnSend(JButton btnSend) {
        this.btnSend = btnSend;
    }
}
