package packetsniffer.ui;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import jpcap.packet.*;
import javax.swing.*;

public abstract class PSStatFrame extends JPanel
{
	PSStatFrame(String title){
		//super(title);
		PSStatFrameUpdate.start();
		//addWindowListener(new java.awt.event.WindowAdapter(){
			//public void windowClosed(java.awt.event.WindowEvent evt){
				//hide();
                setSize(500,500);
				setVisible(false);
			//}
		//});
	}
	abstract void fireUpdate();
	public abstract void addPacket(Packet p);
	public abstract void clear();

	public void startUpdating(){
		PSStatFrameUpdate.setRepeats(true);
		PSStatFrameUpdate.start();
	}
	
	public void stopUpdating(){
		PSStatFrameUpdate.stop();
		PSStatFrameUpdate.setRepeats(false);
		PSStatFrameUpdate.start();
	}

	javax.swing.Timer PSStatFrameUpdate=new javax.swing.Timer(500,new ActionListener(){
		public void actionPerformed(ActionEvent evt){
			fireUpdate();
			repaint();
		}
	});

}
