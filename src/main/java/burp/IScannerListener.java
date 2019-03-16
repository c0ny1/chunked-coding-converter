package burp;/*
 * @(#)burp.IScannerListener.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of burp Suite Free Edition
 * and burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>burp.IBurpExtenderCallbacks.registerScannerListener()</code> to register a
 * Scanner listener. The listener will be notified of new issues that are
 * reported by the Scanner tool. Extensions can perform custom analysis or
 * logging of Scanner issues by registering a Scanner listener.
 */
public interface IScannerListener
{
    /**
     * This method is invoked when a new issue is added to burp Scanner's
     * results.
     *
     * @param issue An
     * <code>burp.IScanIssue</code> object that the extension can query to obtain
     * details about the new issue.
     */
    void newScanIssue(IScanIssue issue);
}
