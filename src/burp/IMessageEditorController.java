package burp;/*
 * @(#)burp.IMessageEditorController.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of burp Suite Free Edition
 * and burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used by an
 * <code>burp.IMessageEditor</code> to obtain details about the currently displayed
 * message. Extensions that create instances of burp's HTTP message editor can
 * optionally provide an implementation of
 * <code>burp.IMessageEditorController</code>, which the editor will invoke when it
 * requires further information about the current message (for example, to send
 * it to another burp tool). Extensions that provide custom editor tabs via an
 * <code>burp.IMessageEditorTabFactory</code> will receive a reference to an
 * <code>burp.IMessageEditorController</code> object for each tab instance they
 * generate, which the tab can invoke if it requires further information about
 * the current message.
 */
public interface IMessageEditorController
{
    /**
     * This method is used to retrieve the HTTP service for the current message.
     *
     * @return The HTTP service for the current message.
     */
    IHttpService getHttpService();

    /**
     * This method is used to retrieve the HTTP request associated with the
     * current message (which may itself be a response).
     *
     * @return The HTTP request associated with the current message.
     */
    byte[] getRequest();

    /**
     * This method is used to retrieve the HTTP response associated with the
     * current message (which may itself be a request).
     *
     * @return The HTTP response associated with the current message.
     */
    byte[] getResponse();
}
