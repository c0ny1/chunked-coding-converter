package burp;

import javax.swing.*;

public class ChunkedLogTable extends JTable {
    private SleepSendTableModel model;

    // 不能命名为getModel,否则表格无法显示
    public SleepSendTableModel getChunkedLogModel() {
        return model;
    }

    public ChunkedLogTable(SleepSendTableModel tableModel) {
        super(tableModel);
        this.model = tableModel;
    }
}