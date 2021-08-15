package burp.sleepchunked;

public class ChunkedInfoEntity {
    private int id = -1;
    private byte[] chunkedContent = new byte[0];
    private int chunkedLen = 0;
    private int sleepTime = 0;
    private String status = "unkown";

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
