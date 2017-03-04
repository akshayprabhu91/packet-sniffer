package packetsniffer.analyzer;
import jpcap.packet.*;
import java.util.Hashtable;
import java.net.InetAddress;
import packetsniffer.PSCaptor;
import packetsniffer.ui.*;
import javax.swing.*;
import java.awt.*;

public class ARPAnalyzer extends PSPacketAnalyzer
{
	private static final String[] valueNames={
		"Hardware Type",
		"Protocol Type",
		"Hardware Address Length",
		"Protocol Address Length",
		"Operation",
		"Sender Hardware Address",
		"Source IP",
		"Target Hardware Address",
		"Destination IP"
	};
        private Hashtable values=new Hashtable();
	private ARPPacket arp;
        int i=0;

	
	public ARPAnalyzer(){
		layer=NETWORK_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		if (p instanceof ARPPacket)
                    return true;
                return false;
	}
	
	public String getProtocolName(){
		return "ARP/RARP";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet p){
		if(!isAnalyzable(p)) return;
		arp=(ARPPacket)p;
                values.clear();
                if(!isAnalyzable(p))	return;
                final ARPPacket arp=(ARPPacket)p;
		values.put(valueNames[0],new Integer(arp.hardtype));
		values.put(valueNames[1],new Integer(arp.prototype));
		values.put(valueNames[2],new Integer(arp.hlen));
		values.put(valueNames[3],new Integer(arp.plen));
		values.put(valueNames[4],getValueAt(4));
		values.put(valueNames[5],getValueAt(5));
		values.put(valueNames[6],getValueAt(6));
		values.put(valueNames[7],getValueAt(7));
		values.put(valueNames[8],getValueAt(8));
                
                
                noti();
                
                
		

                
	}
	
	public Object getValue(String valueName){
		/*for(int i=0;i<valueNames.length;i++)
			if(valueNames[i].equals(valueName))
                        {
                            
				return getValueAt(i);}
		
		return null;*/

     InetAddress addr=null;
            if((valueNames[6].equals(valueName) && values.get(valueName) instanceof InetAddress) ||
		   (valueNames[8].equals(valueName) && values.get(valueName) instanceof InetAddress)){
 
			addr=(InetAddress)values.get(valueName);
                        
			if(PSCaptor.hostnameCache.containsKey(addr))
				values.put(valueName,PSCaptor.hostnameCache.get(addr));
			else{
				values.put(valueName,addr.getAddress());
			} 
		}
               if(addr==null)
		return values.get(valueName);
     return addr;
     
                
	}
	
	Object getValueAt(int index){
		switch(index){
			case 0: 
			switch(arp.hardtype){
				case ARPPacket.HARDTYPE_ETHER: return "Ethernet ("+arp.hardtype+")";
				case ARPPacket.HARDTYPE_IEEE802: return "Token ring ("+arp.hardtype+")";
				case ARPPacket.HARDTYPE_FRAMERELAY: return "Frame relay ("+arp.hardtype+")";
				default: return new Integer(arp.hardtype);
			}
			case 1:
			switch(arp.prototype){
				case ARPPacket.PROTOTYPE_IP: return "IP ("+arp.prototype+")";
				default: return new Integer(arp.prototype);
			}
			case 2: return new Integer(arp.hlen);
			case 3: return new Integer(arp.plen);
			case 4:
			switch(arp.operation){
				case ARPPacket.ARP_REQUEST: return "ARP Request";
				case ARPPacket.ARP_REPLY: return "ARP Reply";
				case ARPPacket.RARP_REQUEST: return "Reverse ARP Request";
				case ARPPacket.RARP_REPLY: return "Reverse ARP Reply";
				case ARPPacket.INV_REQUEST: return "Identify peer Request";
				case ARPPacket.INV_REPLY: return "Identify peer Reply";
				default: return new Integer(arp.operation);
			}
			case 5: return arp.getSenderHardwareAddress();
			case 6: return arp.getSenderProtocolAddress();
			case 7: return arp.getTargetHardwareAddress();
			case 8: return arp.getTargetProtocolAddress();
			default: return null;
		}
	}
	
	public Object[] getValues(){
		Object[] v=new Object[valueNames.length];
		for(int i=0;i<valueNames.length;i++)
			v[i]=getValueAt(i);
		
		return v;
	}
        
        public void noti()
        {
            System.out.println("problem1");
            
            if(values.get("Source IP")==values.get("Destination IP"))
                {   
                    System.out.println("Source IP="+values.get("Source IP"));
                    System.out.println("Destination IP="+values.get("Destination IP"));
                    System.out.println("problem");
                    
                
                    JFrame frame=new JFrame();
                    JPanel p=new JPanel();
                    JLabel l=new JLabel("Land Attack Detected");
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
