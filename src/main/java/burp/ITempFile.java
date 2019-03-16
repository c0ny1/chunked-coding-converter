package burp;/*
 * @(#)burp.ITempFile.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of burp Suite Free Edition
 * and burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to hold details of a temporary file that has been
 * created via a call to
 * <code>burp.IBurpExtenderCallbacks.saveToTempFile()</code>.
 *
 */
public interface ITempFile
{
    /**
     * This method is used to retrieve the contents of the buffer that was saved
     * in the temporary file.
     *
     * @return The contents of the buffer that was saved in the temporary file.
     */
    byte[] getBuffer();

    /**
     * This method is used to permanently delete the temporary file when it is
     * no longer required.
     */
    void delete();
}
