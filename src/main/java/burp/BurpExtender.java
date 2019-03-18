package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender,IHttpListener,IProxyListener {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private String extensionName = "Chunked coding converter";
    private String version ="0.1";
    public static PrintWriter stdout;
    public static PrintWriter stderr;

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

            if(reqInfo.getMethod().equals("POST")){
                try {
                    byte[] request = Transfer.encoding(helpers, messageInfo, Config.getMin_chunked_len(),Config.getMax_chunked_len(),Config.isAddComment(),Config.getMin_comment_len(),Config.getMax_comment_len());
                    if (request != null) {
                        messageInfo.setRequest(request);
                    }
                } catch (Exception e) {
                    e.printStackTrace(stderr);
                }
            }
        }
    }


    @Override
    public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage proxyMessage) {
        if(messageIsRequest && isValidTool(IBurpExtenderCallbacks.TOOL_PROXY)){
            IHttpRequestResponse messageInfo = proxyMessage.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo.getRequest());

            if(reqInfo.getMethod().equals("POST")){
                try {
                    byte[] request = Transfer.encoding(helpers, messageInfo, Config.getMin_chunked_len(),Config.getMax_chunked_len(),Config.isAddComment(),Config.getMin_comment_len(),Config.getMax_comment_len());
                    if (request != null) {
                        messageInfo.setRequest(request);
                    }
                } catch (Exception e) {
                    e.printStackTrace(stderr);
                }
            }
        }
    }


    private boolean isValidTool(int toolFlag){
        return (Config.isAct_on_all_tools() ||
                (Config.isAct_on_proxy() && toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) ||
                (Config.isAct_on_intruder() && toolFlag== IBurpExtenderCallbacks.TOOL_INTRUDER) ||
                (Config.isAct_on_repeater() && toolFlag== IBurpExtenderCallbacks.TOOL_REPEATER) ||
                (Config.isAct_on_scanner() && toolFlag== IBurpExtenderCallbacks.TOOL_SCANNER) ||
                (Config.isAct_on_sequencer() && toolFlag== IBurpExtenderCallbacks.TOOL_SEQUENCER) ||
                (Config.isAct_on_spider() && toolFlag== IBurpExtenderCallbacks.TOOL_SPIDER) ||
                (Config.isAct_on_extender() && toolFlag== IBurpExtenderCallbacks.TOOL_EXTENDER) ||
                (Config.isAct_on_target() && toolFlag== IBurpExtenderCallbacks.TOOL_TARGET));
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
