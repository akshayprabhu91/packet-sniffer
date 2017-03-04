package packetsniffer.ui;
import java.awt.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.border.*;
import java.net.InetAddress;

class PSTableRenderer extends JLabel implements TableCellRenderer
{
	protected static Border noFocusBorder = new EmptyBorder(1, 1, 1, 1); 

	public PSTableRenderer(){
		setOpaque(true);
	}

	public Component getTableCellRendererComponent(JTable table,
			Object value,boolean isSelected,boolean hasFocus,int row,int column){
		
		if(isSelected){
			super.setForeground(table.getSelectionForeground());
			super.setBackground(table.getSelectionBackground());
		}else{
			super.setForeground(table.getForeground());
			super.setBackground(table.getBackground());
		}
		
		setFont(table.getFont());

		if(hasFocus){
	    setBorder( UIManager.getBorder("Table.focusCellHighlightBorder") );
		}else{
			setBorder(noFocusBorder);
		}
		
		if(value==null){

			setText("null");
			return this;
		}
		
		setText(value.toString());

		
		if(value.getClass().equals(Integer.class) || value.getClass().equals(Long.class)){
			setHorizontalAlignment(SwingConstants.RIGHT);
		}
		
		// ---- begin optimization to avoid painting background ----
		Color back = getBackground();
		boolean colorMatch = (back != null) && ( back.equals(table.getBackground()) ) && table.isOpaque();
		setOpaque(!colorMatch);
		// ---- end optimization to aviod painting background ----

		
	
                return this;
}
}