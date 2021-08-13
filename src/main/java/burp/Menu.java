package burp;

import burp.sleepclient.SleepSendDlg;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * 菜单类，负责显示菜单，处理菜单事件
 */
public class Menu implements IContextMenuFactory {
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList();
        JMenu chunkedMenu = new JMenu("Chunked coding converter");
        JMenuItem encodeChunked = new JMenuItem("Encoding request body");
        JMenuItem decodeChunked = new JMenuItem("Decoding request body");
        JMenuItem config = new JMenuItem("Config");
        JMenuItem sleepClient = new JMenuItem("Sleep send client");
        chunkedMenu.add(encodeChunked);
        chunkedMenu.add(decodeChunked);
        chunkedMenu.add(config);
        chunkedMenu.addSeparator();
        chunkedMenu.add(sleepClient);

        //若数据包无法编辑，则将编码解码菜单项设置为禁用
        if(invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
            encodeChunked.setEnabled(false);
            decodeChunked.setEnabled(false);
        }

        encodeChunked.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(iReqResp.getRequest());
                // 不对GET请求进行编码
                if(!reqInfo.getMethod().equals("POST")){
                    JOptionPane.showConfirmDialog(null,"GET requests cannot be chunked encoded！","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // 不重复编码
                if(Transfer.isChunked(iReqResp)){
                    JOptionPane.showConfirmDialog(null,"The request has been chunked encoded，Do not repeat the encoding！","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                try {
                    byte[] request = Transfer.encoding(iReqResp, Config.getMin_chunked_len(),Config.getMax_chunked_len(),Config.isAddComment(),Config.getMin_comment_len(),Config.getMax_comment_len());
                    if (request != null) {
                        iReqResp.setRequest(request);
                    }
                } catch (Exception e) {
                    BurpExtender.stderr.println(e.getMessage());
                }
            }
        });

        decodeChunked.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];

                // 进制对未编码请求解码
                if(!Transfer.isChunked(iReqResp)){
                    JOptionPane.showConfirmDialog(null,"The request is unencoded and cannot be decoded!","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                try {
                    byte[] request = Transfer.decoding(iReqResp);
                    if (request != null) {
                        iReqResp.setRequest(request);
                    }
                } catch (Exception e) {
                    BurpExtender.stderr.println(e.getMessage());
                }
            }
        });

        config.addActionListener(new ActionListener(){

            public void actionPerformed(ActionEvent arg0) {
                try {
                    ConfigDlg dlg = new ConfigDlg();
                    BurpExtender.callbacks.customizeUiComponent(dlg);
                    dlg.setVisible(true);
                }catch (Exception e){
                    e.printStackTrace(BurpExtender.stderr);
                }
            }
        });


        sleepClient.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
                    SleepSendDlg dlg = new SleepSendDlg(iReqResp);
                    BurpExtender.callbacks.customizeUiComponent(dlg);
                    dlg.setVisible(true);
                    dlg.setSize(1150,800);
                }catch (Exception ex){
                    ex.printStackTrace(BurpExtender.stderr);
                }
            }
        });

        menus.add(chunkedMenu);
        return menus;
    }
}