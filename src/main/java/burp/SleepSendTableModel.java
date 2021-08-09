package burp;


import burp.sleepclient.ChunkedInfoEntity;

import javax.swing.table.AbstractTableModel;
import java.util.Vector;

public class SleepSendTableModel extends AbstractTableModel {
	public Vector<String> title = new Vector<String>();

	public SleepSendTableModel() {
		title.clear();
		title.add("id");
		title.add("chunked content");
		title.add("chunked length");
		title.add("sleep time");
		title.add("status");
	}

	@Override
	public String getColumnName(int column) {
		return title.get(column);
	}

	@Override
	public int getColumnCount() {
		return title.size();
	}


	@Override
	public int getRowCount() {
		return SleepSendDlg.chunkedInfos.size();
	}

	@Override
	public Object getValueAt(int row, int column) {
		ChunkedInfoEntity alertEntity = SleepSendDlg.chunkedInfos.get(row);
		switch (column) {
			case 0:
				return alertEntity.getId();
			case 1:
				return new String(alertEntity.getChunkedContent());
			case 2:
				return alertEntity.getChunkedLen();
			case 3:
				return alertEntity.getSleepTime();
			case 4:
				return alertEntity.getStatus();
			default:
				return "";
		}
	}


// 这个引起了界面混乱。
//	/**
//	 * 让使Swing中JTable中的列按各列的数据类型排序
//	 *
//	 * @Reference http://blog.sina.com.cn/s/blog_54b09dc90100ao7d.html
//	 * @param columnIndex
//	 * @return
//	 */
//	@Override
//	public Class<?> getColumnClass(int columnIndex) {
//		return getValueAt(0,columnIndex).getClass();
//	}

}
