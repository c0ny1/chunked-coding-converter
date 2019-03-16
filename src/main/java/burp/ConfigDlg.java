package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class ConfigDlg extends JDialog {
    private final JPanel mainPanel = new JPanel();
    private final JPanel topPanel =  new JPanel();
    private final JPanel centerPanel = new JPanel();
    private final JPanel bottomPanel = new JPanel();;
    private final JLabel lbSplitLen = new JLabel("Length of chunked:");
    private final JSpinner spMinChunkedLen = new JSpinner(new SpinnerNumberModel(1, 1, 100, 1));
    private final JSpinner spMaxChunkedLen = new JSpinner(new SpinnerNumberModel(3, 1, 100, 1));
    private final JCheckBox cbComment = new JCheckBox("Add comments");
    private final JLabel lbCommentLen = new JLabel("Length of comment:");
    private final JSpinner spMinCommentLen = new JSpinner(new SpinnerNumberModel(5, 1, 50, 1));
    private final JLabel lbCommentLenRangeSymbols = new JLabel("-");
    private final JSpinner spMaxCommentLen = new JSpinner(new SpinnerNumberModel(25, 1, 50, 1));
    private final JLabel lbCommentLenRange = new JLabel("(1-50)");
    private final JLabel lbActOnModel = new JLabel("Act on:");
    private final JCheckBox chkAllTools = new JCheckBox("All Tools");
    private final JCheckBox chkSpider = new JCheckBox("Spider");
    private final JCheckBox chkIntruder = new JCheckBox("Intruder");
    private final JCheckBox chkScanner = new JCheckBox("Scanner");
    private final JCheckBox chkRepeater = new JCheckBox("Repeater");
    private final JCheckBox chkSequencer = new JCheckBox("Sequencer");
    private final JCheckBox chkProxy = new JCheckBox("Proxy");
    private final JCheckBox chkExtender = new JCheckBox("Extender");
    private final JCheckBox chkTarget = new JCheckBox("Target");
    private final JButton btSave = new JButton("Save");
    private final JButton btCancel = new JButton("Cancel");


    public ConfigDlg(){
        initGUI();
        initEvent();
        initValue();
        this.setTitle("Chunked coding converter config");
    }


    /**
     * 初始化UI
     */
    private void initGUI(){
        topPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(lbSplitLen);
        topPanel.add(spMinChunkedLen);
        topPanel.add(new JLabel("-"));
        topPanel.add(spMaxChunkedLen);
        topPanel.add(new JLabel("(1-100)"));
        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(cbComment);
        cbComment.setSelected(true);
        topPanel.add(Box.createHorizontalStrut(5));
        topPanel.add(lbCommentLen);
        topPanel.add(spMinCommentLen);
        topPanel.add(lbCommentLenRangeSymbols);
        topPanel.add(spMaxCommentLen);
        topPanel.add(lbCommentLenRange);

        centerPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        centerPanel.add(lbActOnModel);
        centerPanel.add(chkAllTools);
        centerPanel.add(chkTarget);
        centerPanel.add(chkProxy);
        centerPanel.add(chkSpider);
        centerPanel.add(chkIntruder);
        centerPanel.add(chkRepeater);
        centerPanel.add(chkScanner);
        centerPanel.add(chkSequencer);
        centerPanel.add(chkExtender);

        bottomPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
        bottomPanel.add(btSave);
        bottomPanel.add(btCancel);

        mainPanel.setLayout(new BorderLayout());
        mainPanel.add(topPanel,BorderLayout.NORTH);
        mainPanel.add(centerPanel,BorderLayout.CENTER);
        mainPanel.add(bottomPanel,BorderLayout.SOUTH);

        this.setModal(true);
        this.setSize(680,150);
        Dimension screensize=Toolkit.getDefaultToolkit().getScreenSize();
        this.setBounds(screensize.width/2-this.getWidth()/2,screensize.height/2-this.getHeight()/2,this.getWidth(),this.getHeight());
        this.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        this.add(mainPanel);
    }


    /**
     * 初始化事件
     */
    private void initEvent(){
        chkAllTools.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(chkAllTools.isSelected()){
                    chkTarget.setSelected(true);
                    chkProxy.setSelected(true);
                    chkSpider.setSelected(true);
                    chkIntruder.setSelected(true);
                    chkRepeater.setSelected(true);
                    chkScanner.setSelected(true);
                    chkExtender.setSelected(true);
                }else{
                    chkTarget.setSelected(false);
                    chkProxy.setSelected(false);
                    chkSpider.setSelected(false);
                    chkIntruder.setSelected(false);
                    chkRepeater.setSelected(false);
                    chkScanner.setSelected(false);
                    chkExtender.setSelected(false);
                }

            }
        });

        cbComment.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(cbComment.isSelected()){
                    lbCommentLen.setEnabled(true);
                    spMinCommentLen.setEnabled(true);
                    lbCommentLenRangeSymbols.setEnabled(true);
                    spMaxCommentLen.setEnabled(true);
                    lbCommentLenRange.setEnabled(true);

                }else{
                    lbCommentLen.setEnabled(false);
                    spMinCommentLen.setEnabled(false);
                    lbCommentLenRangeSymbols.setEnabled(false);
                    spMaxCommentLen.setEnabled(false);
                    lbCommentLenRange.setEnabled(false);
                }
            }
        });

        btCancel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ConfigDlg.this.dispose();
            }
        });

        btSave.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Integer min_chunked_len = (Integer)spMinChunkedLen.getValue();
                Integer max_chunked_max = (Integer)spMaxChunkedLen.getValue();
                Integer min_comment_len = (Integer)spMinCommentLen.getValue();
                Integer max_comment_len = (Integer)spMaxCommentLen.getValue();

                if(min_chunked_len > max_chunked_max){
                    JOptionPane.showConfirmDialog(ConfigDlg.this,"Please set minimum chunked length less than maximum！","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                if(min_comment_len > max_comment_len){
                    JOptionPane.showConfirmDialog(ConfigDlg.this,"Please set the minimum comment length to be less than the maximum!","Warning",JOptionPane.CLOSED_OPTION,JOptionPane.WARNING_MESSAGE);
                    return;
                }

                Config.min_chunked_len = min_chunked_len;
                Config.max_chunked_len = max_chunked_max;
                Config.addComment = cbComment.isSelected();
                Config.min_comment_len = min_comment_len;
                Config.max_comment_len = max_comment_len;
                Config.act_on_all_tools = chkAllTools.isSelected();
                Config.act_on_target = chkTarget.isSelected();
                Config.act_on_proxy = chkProxy.isSelected();
                Config.act_on_spider = chkSpider.isSelected();
                Config.act_on_intruder = chkIntruder.isSelected();
                Config.act_on_repeater = chkRepeater.isSelected();
                Config.act_on_scanner = chkScanner.isSelected();
                Config.act_on_sequencer = chkSequencer.isSelected();
                Config.act_on_extender = chkExtender.isSelected();
                ConfigDlg.this.dispose();
            }
        });

    }


    /**
     * 为控件赋值
     */
    public void initValue(){
        spMinChunkedLen.setValue(Config.min_chunked_len);
        spMaxChunkedLen.setValue(Config.max_chunked_len);
        cbComment.setSelected(Config.addComment);
        if(cbComment.isSelected()){
            lbCommentLen.setEnabled(true);
            spMinCommentLen.setEnabled(true);
            lbCommentLenRangeSymbols.setEnabled(true);
            spMaxCommentLen.setEnabled(true);
            lbCommentLenRange.setEnabled(true);

        }else{
            lbCommentLen.setEnabled(false);
            spMinCommentLen.setEnabled(false);
            lbCommentLenRangeSymbols.setEnabled(false);
            spMaxCommentLen.setEnabled(false);
            lbCommentLenRange.setEnabled(false);
        }
        spMinCommentLen.setValue(Config.min_comment_len);
        spMaxCommentLen.setValue(Config.max_comment_len);
        chkAllTools.setSelected(Config.act_on_all_tools);
        chkTarget.setSelected(Config.act_on_target);
        chkProxy.setSelected(Config.act_on_proxy);
        chkSpider.setSelected(Config.act_on_spider);
        chkIntruder.setSelected(Config.act_on_intruder);
        chkRepeater.setSelected(Config.act_on_repeater);
        chkScanner.setSelected(Config.act_on_scanner);
        chkSequencer.setSelected(Config.act_on_sequencer);
        chkExtender.setSelected(Config.act_on_extender);
    }
}