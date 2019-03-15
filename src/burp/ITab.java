package burp;/*
 * @(#)burp.ITab.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of burp Suite Free Edition
 * and burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

import java.awt.*;

/**
 * This interface is used to provide burp with details of a custom tab that will
 * be added to burp's UI, using a method such as
 * <code>burp.IBurpExtenderCallbacks.addSuiteTab()</code>.
 */
public interface ITab
{
    /**
     * burp uses this method to obtain the caption that should appear on the
     * custom tab when it is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    String getTabCaption();

    /**
     * burp uses this method to obtain the component that should be used as the
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    Component getUiComponent();
}
