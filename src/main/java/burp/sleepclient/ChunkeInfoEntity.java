package burp.sleepclient;

public class ChunkeInfoEntity {
    private int id;
    private byte[] chunkedContent;
    private int chunkedLen;
    private int sleepTime;
    private String status;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public byte[] getChunkedContent() {
        return chunkedContent;
    }

    public void setChunkedContent(byte[] chunkedContent) {
        this.chunkedContent = chunkedContent;
    }

    public int getChunkedLen() {
        return chunkedLen;
    }

    public void setChunkedLen(int chunkedLen) {
        this.chunkedLen = chunkedLen;
    }

    public int getSleepTime() {
        return sleepTime;
    }

    public void setSleepTime(int sleepTime) {
        this.sleepTime = sleepTime;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
