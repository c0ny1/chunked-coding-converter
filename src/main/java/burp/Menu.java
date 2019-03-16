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


    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList();
        JMenu chunkedMenu = new JMenu("Chunked coding converter");
        JMenuItem encodeChunked = new JMenuItem("Encoding request body");
        JMenuItem decodeChunked = new JMenuItem("Decoding request body");
        JMenuItem config = new JMenuItem("Config");
        chunkedMenu.add(encodeChunked);
        chunkedMenu.add(decodeChunked);
        chunkedMenu.addSeparator();
        chunkedMenu.add(config);

        //若数据包无法编辑，则将编码解码菜单项设置为禁用
        if(invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
            encodeChunked.setEnabled(false);
            decodeChunked.setEnabled(false);
        }

        encodeChunked.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                try {
                    byte[] request = Transfer.encoding(m_helpers, iReqResp, Config.min_chunked_len,Config.max_chunked_len,Config.addComment,Config.min_comment_len,Config.max_comment_len);
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