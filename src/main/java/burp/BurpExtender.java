package burp;

import java.io.PrintWriter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;


public class BurpExtender implements IBurpExtender,IHttpListener,IProxyListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private String extensionName = "Chunked coding converter";
    private String version ="0.1";
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(String.format("%s %s",extensionName,version));
        callbacks.registerContextMenuFactory(new Menu(callbacks));
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        stdout = new PrintWriter(callbacks.getStdout(),true);
        stderr = new PrintWriter(callbacks.getStderr(),true);
        stdout.println(getBanner());
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //代理不走这，否则两次修改会导致数据包存在问题
        if(messageIsRequest && isValidTool(toolFlag) && (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY)){
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo.getRequest());
            //stdout.println(messageInfo.getRequest().toString());
            //stdout.println(reqInfo.getContentType());
            //stdout.println(reqInfo.getMethod());

            if(reqInfo.getMethod().equals("POST") && reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED){
                try {
                    byte[] request = Transfer.encoding(helpers, messageInfo, Config.min_chunked_len,Config.max_chunked_len,Config.addComment,Config.min_comment_len,Config.max_comment_len);
                    if (request != null) {
                        messageInfo.setRequest(request);
                    }
                } catch (Exception e) {
                    stderr.println(e.getMessage());
                }
            }
        }
    }


    @Override
    public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage proxyMessage) {
        if(messageIsRequest && isValidTool(IBurpExtenderCallbacks.TOOL_PROXY)){
            IHttpRequestResponse messageInfo = proxyMessage.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo.getRequest());

            if(reqInfo.getMethod().equals("POST") && reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED){
                try {
                    byte[] request = Transfer.encoding(helpers, messageInfo, Config.min_chunked_len,Config.max_chunked_len,Config.addComment,Config.min_comment_len,Config.max_comment_len);
                    if (request != null) {
                        messageInfo.setRequest(request);
                    }
                } catch (Exception e) {
                    stderr.println(e.getMessage());
                }
            }
        }
    }


    private boolean isValidTool(int toolFlag){
        return (Config.act_on_all_tools ||
                (Config.act_on_proxy && toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) ||
                (Config.act_on_intruder && toolFlag== IBurpExtenderCallbacks.TOOL_INTRUDER) ||
                (Config.act_on_repeater && toolFlag== IBurpExtenderCallbacks.TOOL_REPEATER) ||
                (Config.act_on_scanner && toolFlag== IBurpExtenderCallbacks.TOOL_SCANNER) ||
                (Config.act_on_sequencer && toolFlag== IBurpExtenderCallbacks.TOOL_SEQUENCER) ||
                (Config.act_on_spider && toolFlag== IBurpExtenderCallbacks.TOOL_SPIDER) ||
                (Config.act_on_extender && toolFlag== IBurpExtenderCallbacks.TOOL_EXTENDER) ||
                (Config.act_on_target && toolFlag== IBurpExtenderCallbacks.TOOL_TARGET));
    }


    /**
     * 插件Banner信息
     * @return
     */
    public String getBanner(){
        String bannerInfo =
                "[+]\n"
                        + "[+] ##############################################\n"
                        + "[+]    " + extensionName + " v" + version +"\n"
                        + "[+]    anthor: c0ny1\n"
                        + "[+]    email:  root@gv7.me\n"
                        + "[+]    github: http://github.com/c0ny1/chunked-coding-converter\n"
                        + "[+] ##############################################";
        return bannerInfo;
    }
}
