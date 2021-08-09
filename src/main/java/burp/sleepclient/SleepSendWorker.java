package burp.sleepclient;

import burp.*;

import javax.swing.*;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import static burp.SleepSendDlg.*;

public class SleepSendWorker extends SwingWorker {
    private IHttpRequestResponse iReqResp;
    private int minChunkedLen;
    private int maxChunkedLen;
    private int minSleepTime;
    private int maxSleepTime;


    public SleepSendWorker(IHttpRequestResponse iReqResp,int minChunkedLen,int maxChunkedLen,int minSleepTime,int maxSleepTime){
        this.iReqResp = iReqResp;
        this.minChunkedLen = minChunkedLen;
        this.maxChunkedLen = maxChunkedLen;
        this.minSleepTime = minSleepTime;
        this.maxSleepTime = maxSleepTime;
        SleepSendDlg.chunkedInfos.clear();
        logTable.getHttpLogTableModel().fireTableDataChanged();//通知模型更新
        logTable.updateUI();//刷新表格
    }

    protected Object doInBackground() throws Exception {
        byte[] request = iReqResp.getRequest();
        requestViewer.setMessage(request, true);
        List<String> headers = BurpExtender.helpers.analyzeRequest(request).getHeaders();
        Iterator<String> iter = headers.iterator();
        LinkedHashMap<String, String> mapHeaders = new LinkedHashMap<String, String>();
        while (iter.hasNext()) {
            //不对请求包重复编码
            String item = iter.next();
            if (item.contains(":")) {
                String key = item.substring(0, item.indexOf(":"));
                String value = item.substring(item.indexOf(":") + 1, item.length());
                mapHeaders.put(key.trim(), value.trim());
            }else if(item.contains("HTTP/")){
                mapHeaders.put("top",item);
            }
        }

        IHttpService httpService = iReqResp.getHttpService();
        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(httpService,request);

        String url = requestInfo.getUrl().toString();
        int bodyOffset = requestInfo.getBodyOffset();
        int body_length = request.length - bodyOffset;
        byte[] byteBody = new byte[body_length];
        System.arraycopy(request, bodyOffset, byteBody, 0, body_length);

        SocketSleepClient socketSleepClient = new SocketSleepClient(url,mapHeaders,byteBody);
        socketSleepClient.setMinChunkedLen(minChunkedLen);
        socketSleepClient.setMaxChunkedLen(maxChunkedLen);
        socketSleepClient.setMinSleepTime(minSleepTime);
        socketSleepClient.setMaxSleepTime(maxSleepTime);

        byte[] result = socketSleepClient.send();
        responseViewer.setMessage(result, true);

//        logTable.getHttpLogTableModel().fireTableDataChanged();//通知模型更新
//        logTable.updateUI();//刷新表格
        return null;
    }
}
