package burp;/*
 * @(#)burp.ICookie.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of burp Suite Free Edition
 * and burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.Date;

/**
 * This interface is used to hold details about an HTTP cookie.
 */
public interface ICookie
{
    /**
     * This method is used to retrieve the domain for which the cookie is in
     * scope.
     *
     * @return The domain for which the cookie is in scope. <b>Note:</b> For
     * cookies that have been analyzed from responses (by calling
     * <code>burp.IExtensionHelpers.analyzeResponse()</code> and then
     * <code>burp.IResponseInfo.getCookies()</code>, the domain will be
     * <code>null</code> if the response did not explicitly set a domain
     * attribute for the cookie.
     */
    String getDomain();

    /**
     * This method is used to retrieve the expiration time for the cookie.
     *
     * @return The expiration time for the cookie, or
     * <code>null</code> if none is set (i.e., for non-persistent session
     * cookies).
     */
    Date getExpiration();

    /**
     * This method is used to retrieve the name of the cookie.
     * 
     * @return The name of the cookie.
     */
    String getName();

    /**
     * This method is used to retrieve the value of the cookie.
     * @return The value of the cookie.
     */
    String getValue();
}
