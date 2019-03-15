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
    private final JLabel lbSplitLen = new JLabel("Length of chunked:");;
    private final JSpinner spSplitLen = new JSpinner(new SpinnerNumberModel(2, 1, 100, 1));
    private final JLabel lbRange = new JLabel("(1-100)");
    private final JCheckBox cbComment = new JCheckBox("Add comments");
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
    private void initGUI(){
        topPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(lbSplitLen);
        topPanel.add(spSplitLen);
        topPanel.add(lbRange);
        topPanel.add(cbComment);
        cbComment.setSelected(true);

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
        this.setSize(640,150);
        //this.setSize(mainPanel.getWidth(),mainPanel.getHeight());
        Dimension screensize=Toolkit.getDefaultToolkit().getScreenSize();
        this.setBounds(screensize.width/2-this.getWidth()/2,screensize.height/2-this.getHeight()/2,this.getWidth(),this.getHeight());
        this.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        this.add(mainPanel);
    }

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

        btCancel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                ConfigDlg.this.dispose();
            }
        });

        btSave.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Config.splite_len = (int)spSplitLen.getValue();
                Config.isComment = cbComment.isSelected();
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

    public void initValue(){
        spSplitLen.setValue(Config.splite_len);
        cbComment.setSelected(Config.isComment);
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
