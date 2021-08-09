package burp;

import javax.swing.*;
import javax.swing.table.TableModel;

public class ChunkedLogTable extends JTable {
    private SleepSendTableModel httpLogTableModel;

    public SleepSendTableModel getHttpLogTableModel() {
        return httpLogTableModel;
    }


    public ChunkedLogTable(TableModel tableModel) {
        super(tableModel);
        this.httpLogTableModel = (SleepSendTableModel) tableModel;
    }
}