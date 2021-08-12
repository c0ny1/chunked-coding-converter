package burp;

import javax.swing.*;
import javax.swing.table.TableModel;

public class ChunkedLogTable extends JTable {
    private SleepSendTableModel model;

    public SleepSendTableModel getModel() {
        return model;
    }

    public ChunkedLogTable(TableModel tableModel) {
        super(tableModel);
        this.model = (SleepSendTableModel) tableModel;
    }
}