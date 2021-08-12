package burp.sleepclient;

import burp.*;

import javax.swing.*;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

public class SleepSendWorker extends SwingWorker {
    private IHttpRequestResponse iReqResp;
    private SleepSendConfig sleepSendConfig;

    public SleepSendWorker(IHttpRequestResponse iReqResp,SleepSendConfig config){
        this.iReqResp = iReqResp;
        this.sleepSendConfig = config;
    }

    protected Object doInBackground() throws Exception {
        this.sleepSendConfig.getChunkedLogTable().getChunkedLogModel().getChunkedInfos().clear();
        sleepSendConfig.getChunkedLogTable().getChunkedLogModel().fireTableDataChanged();//通知模型更新
        sleepSendConfig.getChunkedLogTable().updateUI();//刷新表格
        sleepSendConfig.getResponseViewer().setMessage("".getBytes(),true);

        byte[] request = iReqResp.getRequest();
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

        SocketSleepClient socketSleepClient = new SocketSleepClient(url,mapHeaders,byteBody,sleepSendConfig);
        byte[] result = socketSleepClient.send();
        sleepSendConfig.getResponseViewer().setMessage(result, true);

//        logTable.getHttpLogTableModel().fireTableDataChanged();//通知模型更新
//        logTable.updateUI();//刷新表格

        return null;
    }
}
