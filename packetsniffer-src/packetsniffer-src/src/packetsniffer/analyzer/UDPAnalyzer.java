package packetsniffer.analyzer;
import jpcap.packet.*;
import java.awt.*;
import javax.swing.*;

public class UDPAnalyzer extends PSPacketAnalyzer
{
	private static final String[] valueNames={
		"Source Port",
		"Destination Port",
		"Packet Length"
	};
	private UDPPacket udp;
	
	public UDPAnalyzer(){
		layer=TRANSPORT_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		return (p instanceof UDPPacket);
	}
	
	public String getProtocolName(){
		return "UDP";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet p){
		if(!isAnalyzable(p)) return;
		udp=(UDPPacket)p;
                //test();
	}
	
	public Object getValue(String valueName){
		for(int i=0;i<valueNames.length;i++)
			if(valueNames[i].equals(valueName))
				return getValueAt(i);
		
		return null;
	}
	
	public Object getValueAt(int index){
		switch(index){
			case 0: return new Integer(udp.src_port);
			case 1: return new Integer(udp.dst_port);
			case 2: return new Integer(udp.length);
			default: return null;
		}
	}
	
	public Object[] getValues(){
		Object[] v=new Object[3];
		for(int i=0;i<3;i++)
			v[i]=getValueAt(i);
		
		return v;
	}
        
        public void test(Packet packet)
        {
            analyze(packet);
            if(("7".equals(getValueAt(1).toString())) || ("19".equals(getValueAt(1).toString())))
            {
                System.out.println("smurf attack detected");
                JFrame frame=new JFrame();
                                            JPanel p=new JPanel();
                                            JLabel l=new JLabel("Fraggle Detected");
                                            JButton ok=new JButton("OK");
                                            JButton report=new JButton("REPORT");

                                            frame.setLayout(new BorderLayout());
                                            p.setLayout(new FlowLayout());

                                            frame.add(l,BorderLayout.CENTER);
                                            p.add(ok);
                                            p.add(report);
                                            frame.add(p,BorderLayout.SOUTH);
                                            frame.setSize(400,100);
                                            frame.setVisible(true);
            
            }
        }
}
