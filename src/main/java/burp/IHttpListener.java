package burp;/*
 * @(#)burp.IHttpListener.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of burp Suite Free Edition
 * and burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>burp.IBurpExtenderCallbacks.registerHttpListener()</code> to register an
 * HTTP listener. The listener will be notified of requests and responses made
 * by any burp tool. Extensions can perform custom analysis or modification of
 * these messages by registering an HTTP listener.
 */
public interface IHttpListener
{
    /**
     * This method is invoked when an HTTP request is about to be issued, and
     * when an HTTP response has been received.
     *
     * @param toolFlag A flag indicating the burp tool that issued the request.
     * burp tool flags are defined in the
     * <code>burp.IBurpExtenderCallbacks</code> interface.
     * @param messageIsRequest Flags whether the method is being invoked for a
     * request or response.
     * @param messageInfo Details of the request / response to be processed.
     * Extensions can call the setter methods on this object to update the
     * current message and so modify burp's behavior.
     */
    void processHttpMessage(int toolFlag,
                            boolean messageIsRequest,
                            IHttpRequestResponse messageInfo);
}
