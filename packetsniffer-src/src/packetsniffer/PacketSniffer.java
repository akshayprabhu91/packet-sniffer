package packetsniffer;

import java.util.ArrayList;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import javax.swing.JOptionPane;
import javax.swing.UIManager;

import packetsniffer.ui.PSFrame;
import jpcap.NetworkInterface;

public class PacketSniffer
{
	public static Preferences preferences;
	
	public static javax.swing.JFileChooser chooser;

	private static ArrayList<PSFrame> frames=new ArrayList<PSFrame>();

	public static void main(String[] args) throws Exception{
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		chooser=new javax.swing.JFileChooser();
		try{
			Class.forName("jpcap.JpcapCaptor");
			NetworkInterface[] devices=jpcap.JpcapCaptor.getDeviceList();
			if(devices.length==0){
				JOptionPane.showMessageDialog(null,"No network interface found.\nYou need to be admin/su to capture packets.",
						"Warning",JOptionPane.WARNING_MESSAGE);
			}
		}catch(ClassNotFoundException e){
			JOptionPane.showMessageDialog(null,"Cannot find Jpcap. Please install Jpcap.",
					"Error",JOptionPane.ERROR_MESSAGE);
			System.exit(-1);
		}catch(UnsatisfiedLinkError e){
			JOptionPane.showMessageDialog(null,"Cannot find Jpcap and/or libpcap/WinPcap.\n Please install Jpcap and libpcap/WinPcap.",
					"Error",JOptionPane.ERROR_MESSAGE);
			System.exit(-1);
		}
		
		preferences=Preferences.userNodeForPackage(PacketSniffer.class);
		
		PSPacketAnalyzerLoader.loadDefaultAnalyzer();
		PSStatisticsTakerLoader.loadStatisticsTaker();
		
		openNewWindow();
	}
	
	public static void saveProperty(){
		try{
			preferences.flush();
		} catch (BackingStoreException e) {
			JOptionPane.showMessageDialog(null,"Could not save preferences.",
					"Error",JOptionPane.ERROR_MESSAGE);
		}
	}
	
	public static void openNewWindow(){
		PSCaptor captor=new PSCaptor();
		frames.add(PSFrame.openNewWindow(captor));
	}
	
	public static void closeWindow(PSFrame frame){
		frame.captor.stopCapture();
		frame.captor.saveIfNot();
		frame.captor.closeAllWindows();
		frames.remove(frame);
		frame.dispose();
		if(frames.isEmpty()){
			saveProperty();
			System.exit(0);
		}
	}
	
	protected void finalize() throws Throwable{
		saveProperty();
	}
}
