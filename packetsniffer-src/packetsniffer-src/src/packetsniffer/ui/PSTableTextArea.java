package packetsniffer.ui;
import jpcap.packet.*;
import javax.swing.*;

class JDTableTextArea extends JTextArea
{
	JDTableTextArea(){
		super();
		
		setLineWrap(true);
		setEditable(false);
	}
	
	void showPacket(Packet p){
		byte[] bytes=new byte[p.header.length+p.data.length];
		
		System.arraycopy(p.header,0,bytes,0,p.header.length);
		System.arraycopy(p.data,0,bytes,p.header.length,p.data.length);
		
		StringBuffer buf=new StringBuffer();
		for(int i=0,j;i<bytes.length;){
			for(j=0;j<8 && i<bytes.length;j++,i++){
				String d=Integer.toHexString((int)(bytes[i]&0xff));
				buf.append((d.length()==1?"0"+d:d)+" ");
			 if(bytes[i]<32 || bytes[i]>126) bytes[i]=46;
			}
			buf.append("["+new String(bytes,i-j,j)+"]\n");
		}
		
		setText(buf.toString());
		setCaretPosition(0);
	}
}
