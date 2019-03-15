package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class Menu implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers m_helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;

    public Menu(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.m_helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);
    }

    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation)
    {
        List<JMenuItem> menus = new ArrayList();
        if ((invocation.getToolFlag() != 32) && (invocation.getInvocationContext() != 0)) {
            return menus;
        }
        JMenu chunkedMenu = new JMenu("Chunked coding converter");
        JMenuItem encodeChunked = new JMenuItem("Encoding request body");
        JMenuItem decodeChunked = new JMenuItem("Decoding request body");
        JMenuItem config = new JMenuItem("Config");
        chunkedMenu.add(encodeChunked);
        chunkedMenu.add(decodeChunked);
        chunkedMenu.addSeparator();
        chunkedMenu.add(config);

        encodeChunked.addActionListener(new ActionListener(){

        public void actionPerformed(ActionEvent arg0) {
            IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
            try {
                byte[] request = Transfer.encoding(m_helpers, iReqResp, Config.splite_len,Config.isComment);
                if (request != null) {
                    iReqResp.setRequest(request);
                }
            } catch (Exception e) {
                stderr.println(e.getMessage());
            }
        }
    });

        decodeChunked.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                try {
                    byte[] request = Transfer.decoding(m_helpers,iReqResp);
                    if (request != null) {
                        iReqResp.setRequest(request);
                    }
                } catch (Exception e) {
                    stderr.println(e.getMessage());
                }
            }
        });

        config.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                ConfigDlg dlg = new ConfigDlg();
                callbacks.customizeUiComponent(dlg);
                dlg.setVisible(true);
            }
        });

        menus.add(chunkedMenu);
        return menus;
    }
}