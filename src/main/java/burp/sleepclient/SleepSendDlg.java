package burp.sleepclient;

import burp.*;
import burp.utils.DateUtil;
import burp.utils.GBC;
import burp.utils.Util;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class SleepSendDlg extends JDialog {
    private final IHttpRequestResponse iReqResp;
    private JPanel contentPane;
    private JLabel lbHost;
    private final JSpinner spMinChunkedLen = new JSpinner(new SpinnerNumberModel(5, 1, 50, 1));
    private final JLabel lbCommentLenRangeSymbols = new JLabel("-");
    private final JSpinner spMaxChunkedLen = new JSpinner(new SpinnerNumberModel(25, 1, 50, 1));
    private JLabel lbUsername;
    private final JSpinner spMinSleepTime = new JSpinner(new SpinnerNumberModel(0, 0, 10000, 1));
    private final JLabel lbSleepTimeRangeSymbols = new JLabel("-");
    private final JSpinner spMaxSleepTime = new JSpinner(new SpinnerNumberModel(1000, 0, 30000, 1));
    private JCheckBox cbSocks5Proxy;
    private JTextField tfProxyHost;
    private JTextField tfProxyPort;
    private JButton btnSend;
    private JButton btnClear;
    private JSplitPane splitPane;
    public  ChunkedLogTable logTable;
    public JLabel lbMinMaxTotalTime;
    public JLabel lbRequestCount;
    private JLabel lbChunkedLenMinMax;
    public JLabel lbTotalChunked;
    public  JLabel lbTotalTime;

    public  IMessageEditor requestViewer;
    public  IMessageEditor responseViewer;

    private int minChunked;
    private int maxChunked;

    public double minTotalTime;
    private double maxTotalTime;
    private JProgressBar pgBar;



    private SleepSendWorker worker;


    public SleepSendDlg(final IHttpRequestResponse iReqResp) {
        this.iReqResp = iReqResp;
        this.setLayout(new GridBagLayout());
        String title = String.format("sleep send client (%s)", Util.getUrlFormIReqRsp(this.iReqResp));
        this.setTitle(title);
        contentPane = new JPanel();
        GBC gbclist = new GBC(0, 0).setFill(GBC.BOTH).setWeight(100, 100);
        this.add(contentPane,gbclist);
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));

        ////////////////////////////////////////////////////////////////////
        // topPanel start
        ////////////////////////////////////////////////////////////////////
        JPanel topPanel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[] { 0, 0 };
        gridBagLayout.rowHeights = new int[] { 40, 32, 0, 0 };
        gridBagLayout.columnWeights = new double[] { 1.0D, Double.MIN_VALUE };
        gridBagLayout.rowWeights = new double[] { 0.0D, 0.0D, 1.0D, Double.MIN_VALUE };
        topPanel.setLayout(gridBagLayout);

        JPanel ConfigPanel = new JPanel();
        GridBagConstraints gbc_panel = new GridBagConstraints();
        gbc_panel.insets = new Insets(5, 5, 5, 5);
        gbc_panel.fill = 2;
        gbc_panel.gridx = 0;
        gbc_panel.gridy = 0;
        topPanel.add(ConfigPanel, gbc_panel);

        GridBagLayout gbl_panel = new GridBagLayout();
        gbl_panel.columnWidths = new int[] { 40, 100, 0, 39, 33, 25, 0, 0, 0 };
        gbl_panel.rowHeights = new int[] { 0, 0 };
        gbl_panel.columnWeights = new double[] { 0.0D, 0.0D, 0.0D, 0.0D, 0.0D, 0.0D,0.0D, 0.0D, 0.0D, 0.0D, 1.0D, 0.0D,0.0D, Double.MIN_VALUE };
        gbl_panel.rowWeights = new double[] { 0.0D, Double.MIN_VALUE };
        ConfigPanel.setLayout(gbl_panel);

        lbHost = new JLabel("chunked length:");
        GridBagConstraints gbc_lbHost = new GridBagConstraints();
        gbc_lbHost.fill = 2;
        gbc_lbHost.insets = new Insets(0, 0, 0, 5);
        gbc_lbHost.gridx = 0;
        gbc_lbHost.gridy = 0;
        ConfigPanel.add(lbHost, gbc_lbHost);


        GridBagConstraints gbc_tfHost = new GridBagConstraints();
        gbc_tfHost.fill = 2;
        gbc_tfHost.insets = new Insets(0, 0, 0, 5);
        gbc_tfHost.gridx = 1;
        gbc_tfHost.gridy = 0;
        ConfigPanel.add(spMinChunkedLen, gbc_tfHost);


        GridBagConstraints gbc_lbPort = new GridBagConstraints();
        gbc_lbPort.fill = 2;
        gbc_lbPort.insets = new Insets(0, 0, 0, 5);
        gbc_lbPort.gridx = 2;
        gbc_lbPort.gridy = 0;
        ConfigPanel.add(lbCommentLenRangeSymbols, gbc_lbPort);


        GridBagConstraints gbc_tfPort = new GridBagConstraints();
        gbc_tfPort.fill = 2;
        gbc_tfPort.insets = new Insets(0, 0, 0, 5);
        gbc_tfPort.gridx = 3;
        gbc_tfPort.gridy = 0;
        ConfigPanel.add(spMaxChunkedLen, gbc_tfPort);

        lbUsername = new JLabel("sleep time");
        GridBagConstraints gbc_lbUsername = new GridBagConstraints();
        gbc_lbUsername.fill = 2;
        gbc_lbUsername.insets = new Insets(0, 0, 0, 5);
        gbc_lbUsername.gridx = 4;
        gbc_lbUsername.gridy = 0;
        ConfigPanel.add(lbUsername, gbc_lbUsername);


        GridBagConstraints gbc_tfUsername = new GridBagConstraints();
        gbc_tfUsername.fill = 2;
        gbc_tfUsername.insets = new Insets(0, 0, 0, 5);
        gbc_tfUsername.gridx = 5;
        gbc_tfUsername.gridy = 0;
        ConfigPanel.add(spMinSleepTime, gbc_tfUsername);


        GridBagConstraints gbc_lbPassword = new GridBagConstraints();
        gbc_lbPassword.fill = 2;
        gbc_lbPassword.insets = new Insets(0, 0, 0, 5);
        gbc_lbPassword.gridx = 6;
        gbc_lbPassword.gridy = 0;
        ConfigPanel.add(lbSleepTimeRangeSymbols, gbc_lbPassword);


        GridBagConstraints gbc_tfPassword = new GridBagConstraints();
        gbc_tfPassword.fill = 2;
        gbc_tfPassword.insets = new Insets(0, 0, 0, 5);
        gbc_tfPassword.gridx = 7;
        gbc_tfPassword.gridy = 0;
        ConfigPanel.add(spMaxSleepTime, gbc_tfPassword);

        GridBagConstraints gbc_lb1 = new GridBagConstraints();
        gbc_lb1.anchor = 15;
        gbc_lb1.insets = new Insets(0, 0, 0, 5);
        gbc_lb1.gridx = 12;
        gbc_lb1.gridy = 0;
        ConfigPanel.add(new JLabel(""), gbc_lb1);

        btnSend = new JButton("Start");
        btnSend.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    if(btnSend.getText().equals("Start")) {
                        btnSend.setText("Stop");
                        SleepSendConfig sleepSendConfig = getSleepSendConfig();
                        worker = new SleepSendWorker(iReqResp, sleepSendConfig);
                        worker.execute();
                    }else{
                        worker.cancel(true);
                        btnSend.setText("Start");
                    }
                }catch (Throwable throwable){
                    btnSend.setText("Start");
                    throwable.printStackTrace(BurpExtender.stderr);
                }
            }
        });

        GridBagConstraints gbc_btnConn = new GridBagConstraints();
        gbc_btnConn.fill = 2;
        gbc_btnConn.insets = new Insets(0, 0, 0, 5);
        gbc_btnConn.gridx = 13;
        gbc_btnConn.gridy = 0;
        ConfigPanel.add(btnSend, gbc_btnConn);

        btnClear = new JButton("Clear");
        btnClear.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int n = JOptionPane.showConfirmDialog(null, "Are you sure you want to clear the data？", "Passvie Scan Client prompt", JOptionPane.YES_NO_OPTION);
                if(n == 0) {
                    logTable.getChunkedLogModel().getChunkedInfos().clear();
                    logTable.getChunkedLogModel().fireTableDataChanged();//通知模型更新
                    logTable.updateUI();//刷新表格
                    responseViewer.setMessage("".getBytes(),false);
                }
            }
        });
        GridBagConstraints gbc_btnClear = new GridBagConstraints();
        gbc_btnClear.fill = 2;
        gbc_btnClear.insets = new Insets(0, 0, 0, 5);
        gbc_btnClear.gridx = 14;
        gbc_btnClear.gridy = 0;
        ConfigPanel.add(btnClear, gbc_btnClear);
        ////////////////////////////////////////////////////////////////////

        JPanel FilterPanel = new JPanel();
        GridBagConstraints gbc_panel_1 = new GridBagConstraints();
        gbc_panel_1.insets = new Insets(0, 5, 5, 5);
        gbc_panel_1.fill = 2;
        gbc_panel_1.gridx = 0;
        gbc_panel_1.gridy = 1;
        topPanel.add(FilterPanel, gbc_panel_1);
        GridBagLayout gbl_panel_1 = new GridBagLayout();
        gbl_panel_1.columnWidths = new int[] { 40, 225, 0, 0, 0 };
        gbl_panel_1.rowHeights = new int[] { 0, 0 };
        gbl_panel_1.columnWeights = new double[] {0.0D, 0.0D, 0.0D, 0.0D,0.1D,0.0D, 0.0D, 0.0D,0.0D,0.0D,0.0D,0.0D,0.0D,Double.MIN_VALUE };
        gbl_panel_1.rowWeights = new double[] { 0.0D, Double.MIN_VALUE };
        FilterPanel.setLayout(gbl_panel_1);


        int second_row_gridx = 0;
        cbSocks5Proxy = new JCheckBox("socks5 proxy host:");
        GridBagConstraints gbc_enable_socks5 = new GridBagConstraints();
        gbc_enable_socks5.insets = new Insets(0, 0, 0, 5);
        //gbc_enable_socks5.anchor = 13;
        gbc_enable_socks5.fill = 2;
        gbc_enable_socks5.gridx = second_row_gridx;
        gbc_enable_socks5.gridy = 0;
        FilterPanel.add(cbSocks5Proxy, gbc_enable_socks5);
        second_row_gridx++;


        tfProxyHost = new JTextField(10);
        tfProxyHost.setText("127.0.0.1");
        tfProxyHost.setEnabled(false);
        GridBagConstraints gbc_tfDomain = new GridBagConstraints();
        gbc_tfDomain.insets = new Insets(0, 0, 0, 5);
        gbc_tfDomain.fill = 2;
        gbc_tfDomain.gridx = second_row_gridx;
        gbc_tfDomain.gridy = 0;
        FilterPanel.add(tfProxyHost, gbc_tfDomain);
        second_row_gridx++;


        JLabel lbExcludeSuffix = new JLabel("port:");
        GridBagConstraints gbc_lbExcludeSuffix = new GridBagConstraints();
        gbc_lbExcludeSuffix.insets = new Insets(0, 0, 0, 5);
        gbc_lbExcludeSuffix.fill = 2;
        gbc_lbExcludeSuffix.gridx = second_row_gridx;
        gbc_lbExcludeSuffix.gridy = 0;
        FilterPanel.add(lbExcludeSuffix, gbc_lbExcludeSuffix);
        second_row_gridx++;

        tfProxyPort = new JTextField(5);
        tfProxyPort.setText("1080");
        tfProxyPort.setEnabled(false);
        GridBagConstraints gbc_tfExcludeSuffix = new GridBagConstraints();
        gbc_tfExcludeSuffix.insets = new Insets(0, 0, 0, 5);
        gbc_tfExcludeSuffix.fill = 2;
        gbc_tfExcludeSuffix.gridx = second_row_gridx;
        gbc_tfExcludeSuffix.gridy = 0;
        FilterPanel.add(tfProxyPort, gbc_tfExcludeSuffix);
        second_row_gridx++;


        GridBagConstraints gbc_vb = new GridBagConstraints();
        gbc_vb.insets = new Insets(0, 0, 0, 5);
        gbc_vb.fill = 2;
        gbc_vb.gridx = second_row_gridx;
        gbc_vb.gridy = 0;
        FilterPanel.add(Box.createVerticalBox(), gbc_vb);
        second_row_gridx++;

        JLabel lbRequest = new JLabel("body size:");
        GridBagConstraints gbc_lbRequest = new GridBagConstraints();
        gbc_lbRequest.insets = new Insets(0, 0, 0, 5);
        gbc_lbRequest.fill = 2;
        gbc_lbRequest.gridx = second_row_gridx;
        gbc_lbRequest.gridy = 0;
        FilterPanel.add(lbRequest, gbc_lbRequest);
        second_row_gridx++;


        int reqBodyLen = Util.getReqBodyLenFormIReqRsp(iReqResp);
        lbRequestCount = new JLabel(String.valueOf(reqBodyLen));
        lbRequestCount.setForeground(new Color(0,0,255));
        GridBagConstraints gbc_lbRequestCount = new GridBagConstraints();
        gbc_lbRequestCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbRequestCount.fill = 2;
        gbc_lbRequestCount.gridx = second_row_gridx;
        gbc_lbRequestCount.gridy = 0;
        FilterPanel.add(lbRequestCount, gbc_lbRequestCount);
        second_row_gridx++;

        GridBagConstraints gbc_vb2 = new GridBagConstraints();
        gbc_vb2.insets = new Insets(0, 0, 0, 5);
        gbc_vb2.fill = 2;
        gbc_vb2.gridx = second_row_gridx;
        gbc_vb2.gridy = 0;
        FilterPanel.add(Box.createVerticalBox(), gbc_vb);
        second_row_gridx++;

        JLabel lbSucces = new JLabel("sented chunked:");
        GridBagConstraints gbc_lbSucces = new GridBagConstraints();
        gbc_lbSucces.insets = new Insets(0, 0, 0, 5);
        gbc_lbSucces.fill = 2;
        gbc_lbSucces.gridx = second_row_gridx;
        gbc_lbSucces.gridy = 0;
        FilterPanel.add(lbSucces, gbc_lbSucces);
        second_row_gridx++;


        lbTotalChunked = new JLabel("0");
        lbTotalChunked.setForeground(new Color(0, 255, 0));
        GridBagConstraints gbc_lbSuccesCount = new GridBagConstraints();
        gbc_lbSuccesCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbSuccesCount.fill = 2;
        gbc_lbSuccesCount.gridx = second_row_gridx;
        gbc_lbSuccesCount.gridy = 0;
        FilterPanel.add(lbTotalChunked, gbc_lbSuccesCount);
        second_row_gridx++;


        lbChunkedLenMinMax = new JLabel();
        lbChunkedLenMinMax.setForeground(new Color(0, 255, 0));
        GridBagConstraints gbc_chunkedlen_minmax = new GridBagConstraints();
        gbc_chunkedlen_minmax.insets = new Insets(0, 0, 0, 5);
        gbc_chunkedlen_minmax.fill = 2;
        gbc_chunkedlen_minmax.gridx = second_row_gridx;
        gbc_chunkedlen_minmax.gridy = 0;
        FilterPanel.add(lbChunkedLenMinMax, gbc_chunkedlen_minmax);
        second_row_gridx++;

        GridBagConstraints gbc_vb3 = new GridBagConstraints();
        gbc_vb3.insets = new Insets(0, 0, 0, 5);
        gbc_vb3.fill = 2;
        gbc_vb3.gridx = second_row_gridx;
        gbc_vb3.gridy = 0;
        FilterPanel.add(Box.createVerticalBox(), gbc_vb3);
        second_row_gridx++;

        lbTotalTime = new JLabel("send time:");
        GridBagConstraints gbc_lbFail = new GridBagConstraints();
        gbc_lbFail.insets = new Insets(0, 0, 0, 5);
        gbc_lbFail.fill = 2;
        gbc_lbFail.gridx = second_row_gridx;
        gbc_lbFail.gridy = 0;
        FilterPanel.add(lbTotalTime, gbc_lbFail);
        second_row_gridx++;

        lbTotalTime = new JLabel("0s");
        lbTotalTime.setForeground(new Color(255, 0, 0));
        GridBagConstraints gbc_lbFailCount = new GridBagConstraints();
        gbc_lbFailCount.insets = new Insets(0, 0, 0, 5);
        gbc_lbFailCount.fill = 2;
        gbc_lbFailCount.gridx = second_row_gridx;
        gbc_lbFailCount.gridy = 0;
        FilterPanel.add(lbTotalTime, gbc_lbFailCount);
        second_row_gridx++;

        lbMinMaxTotalTime = new JLabel();
        lbMinMaxTotalTime.setForeground(new Color(255, 0, 0));
        GridBagConstraints gbc_minmax_totaltime = new GridBagConstraints();
        gbc_minmax_totaltime.insets = new Insets(0, 0, 0, 5);
        gbc_minmax_totaltime.fill = 2;
        gbc_minmax_totaltime.gridx = second_row_gridx;
        gbc_minmax_totaltime.gridy = 0;
        FilterPanel.add(lbMinMaxTotalTime, gbc_minmax_totaltime);
        second_row_gridx++;

        contentPane.add(topPanel,BorderLayout.NORTH);
        ////////////////////////////////////////////////////////////////////
        // topPanl end
        ////////////////////////////////////////////////////////////////////

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        contentPane.add(splitPane, BorderLayout.CENTER);

        SleepSendTableModel model = new SleepSendTableModel();
        logTable = new ChunkedLogTable(model);

        JTabbedPane tabs = new JTabbedPane();
        requestViewer = BurpExtender.callbacks.createMessageEditor(null, false);
        responseViewer = BurpExtender.callbacks.createMessageEditor(null, false);

        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Response", responseViewer.getComponent());
        splitPane.setTopComponent(tabs);

        JScrollPane jspLogTable = new JScrollPane(logTable);
        splitPane.setBottomComponent(jspLogTable);


        pgBar = new JProgressBar();
        pgBar.setMinimum(0);
        pgBar.setMaximum(reqBodyLen + 1);
        contentPane.add(pgBar,BorderLayout.SOUTH);

        BurpExtender.callbacks.customizeUiComponent(topPanel);
        BurpExtender.callbacks.customizeUiComponent(btnSend);
        BurpExtender.callbacks.customizeUiComponent(splitPane);
        BurpExtender.callbacks.customizeUiComponent(contentPane);

        //this.pack();
        this.setSize(1150,800);
        Dimension screensize=Toolkit.getDefaultToolkit().getScreenSize();
        this.setBounds(screensize.width/2-this.getWidth()/2,screensize.height/2-this.getHeight()/2,this.getWidth(),this.getHeight());

        initAction();
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                byte[] request = iReqResp.getRequest();
                requestViewer.setMessage(request,true);
                splitPane.setDividerLocation(0.5);
                calcTotalChunked();
                calcTotalTime();
            }
        });
    }

    public SleepSendWorker getWorker() {
        return worker;
    }

    public class ChangeListenerImpl implements ChangeListener{
        @Override
        public void stateChanged(ChangeEvent e) {
            int minChunkedLen = (Integer)spMinChunkedLen.getValue();
            int maxChunkedLen = (Integer)spMaxChunkedLen.getValue();

            if(minChunkedLen > maxChunkedLen){
                spMinChunkedLen.setValue(maxChunkedLen);
            }


            int minSleepTime = (Integer)spMinSleepTime.getValue();
            int maxSleepTime = (Integer)spMaxSleepTime.getValue();
            if(minSleepTime > maxSleepTime){
                spMinSleepTime.setValue(maxSleepTime);
            }


            calcTotalChunked();
            calcTotalTime();
        }
    }


    private void initAction(){
        this.addWindowListener(new CloseDialogActionListener(this));
        ChangeListenerImpl changeListener = new ChangeListenerImpl();
        spMinChunkedLen.addChangeListener(changeListener);
        spMaxChunkedLen.addChangeListener(changeListener);
        spMinSleepTime.addChangeListener(changeListener);
        spMaxSleepTime.addChangeListener(changeListener);
        cbSocks5Proxy.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(cbSocks5Proxy.isSelected()){
                    tfProxyHost.setEnabled(true);
                    tfProxyPort.setEnabled(true);
                }else{
                    tfProxyHost.setEnabled(false);
                    tfProxyPort.setEnabled(false);
                }
            }
        });

    }


    private SleepSendConfig getSleepSendConfig(){
        SleepSendConfig config = new SleepSendConfig();

        int minChunkedLen = (Integer)spMinChunkedLen.getValue();
        int maxChunkedLen = (Integer)spMaxChunkedLen.getValue();
        int minSleepTime = (Integer)spMinSleepTime.getValue();
        int maxSleepTime = (Integer)spMaxSleepTime.getValue();

        config.setMinChunkedLen(minChunkedLen);
        config.setMaxChunkedLen(maxChunkedLen);
        config.setMinSleepTime(minSleepTime);
        config.setMaxSleepTime(maxSleepTime);
        config.setLbTotalChunked(lbTotalChunked);
        config.setLbTotalTime(lbTotalTime);
        config.setChunkedLogTable(logTable);
        config.setResponseViewer(responseViewer);
        config.setPgBar(pgBar);
        config.setBtnSend(btnSend);

        config.setEnableSocks5Proxy(cbSocks5Proxy.isSelected());
        config.setProxyHost(tfProxyHost.getText());

        int proxyPort = 0;

        try {
            proxyPort = Integer.valueOf(tfProxyPort.getText());
            if(proxyPort<0 || proxyPort > 65535){
                JOptionPane.showMessageDialog(this,"chunked coding converter","port must be 0~65536",JOptionPane.ERROR);
                return null;
            }
        }catch (Exception e){
            JOptionPane.showMessageDialog(this,"chunked coding converter",e.getMessage(),JOptionPane.ERROR);
            return null;
        }

        config.setProxyPort(proxyPort);
        return config;
    }




    private void calcTotalChunked(){
        double reqBodyLen = Util.getReqBodyLenFormIReqRsp(iReqResp) * 1.0;
        minChunked = getInt(reqBodyLen/ ((Integer) spMaxChunkedLen.getValue()));
        if(minChunked == 0){
            minChunked = 1;
        }
        maxChunked = getInt(reqBodyLen / ((Integer) spMinChunkedLen.getValue()));
        String chunkedLenMinMax = String.format("(%d ~ %d)",minChunked,maxChunked);
        lbChunkedLenMinMax.setText(chunkedLenMinMax);
    }

    private void calcTotalTime(){
        int minSleepTime = (Integer)spMinSleepTime.getValue();
        if(minSleepTime == 0){
            minSleepTime = 1;
        }
        minTotalTime = (minChunked + 1) * minSleepTime;
        maxTotalTime = (maxChunked + 1) * (Integer)spMaxSleepTime.getValue();
        String minMaxTotalTime = String.format("(%s ~ %s)", DateUtil.ms2str(minTotalTime),DateUtil.ms2str(maxTotalTime));
        lbMinMaxTotalTime.setText(minMaxTotalTime);
    }

    public JLabel getLbTotalChunked(){
        return lbTotalChunked;
    }


    public static int getInt(double number){
        int newNumber = (int)number;
        if(number > newNumber){
            return newNumber + 1;
        }else{
            return newNumber;
        }
    }

    private class CloseDialogActionListener implements WindowListener{
        SleepSendDlg sleepSendDlg;
        public CloseDialogActionListener(SleepSendDlg sleepSendDlg){
            this.sleepSendDlg = sleepSendDlg;
        }

        @Override
        public void windowOpened(WindowEvent e) {

        }

        @Override
        public void windowClosing(WindowEvent e) {
            int n = JOptionPane.showConfirmDialog(sleepSendDlg, "Are you sure you want to close the current window？", "sleep send client prompt", JOptionPane.YES_NO_OPTION);
            if(n == JOptionPane.OK_OPTION) {
                if(sleepSendDlg.getWorker() != null){
                    sleepSendDlg.getWorker().cancel(true);
                }
            }else{
                sleepSendDlg.setVisible(true);
            }
        }

        @Override
        public void windowClosed(WindowEvent e) {

        }

        @Override
        public void windowIconified(WindowEvent e) {

        }

        @Override
        public void windowDeiconified(WindowEvent e) {

        }

        @Override
        public void windowActivated(WindowEvent e) {

        }

        @Override
        public void windowDeactivated(WindowEvent e) {

        }
    }
}