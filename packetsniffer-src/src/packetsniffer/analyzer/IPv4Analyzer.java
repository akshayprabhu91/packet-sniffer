package packetsniffer.analyzer;
import java.net.InetAddress;
import java.util.Hashtable;
import java.net.*;
import java.util.*;

import packetsniffer.PSCaptor;

import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import javax.swing.*;
import java.awt.*;

public class IPv4Analyzer extends PSPacketAnalyzer
{
	private static final String[] valueNames={"Version",
		"TOS: Priority",
		"TOS: Throughput",
		"TOS: Reliability",
		"Length",
		"Identification",
		"Fragment: Don't Fragment",
		"Fragment: More Fragment",
		"Fragment Offset",
		"Time To Live",
		"Protocol",
		"Source IP",
		"Destination IP",
		"Source Host Name",
		"Destination Host Name"};

                private static final String[] cmpNames={"UDPProto","ICMPProto"};

	private Hashtable values=new Hashtable();
        private Hashtable cmp=new Hashtable();
        

        int i=0;


      
	
	public IPv4Analyzer(){
		layer=NETWORK_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		if(p instanceof IPPacket && ((IPPacket)p).version==4) return true;
		else return false;
	}
	
	public String getProtocolName(){
		return "IPv4";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet packet){
		values.clear();
		if(!isAnalyzable(packet))	return;
		final IPPacket ip=(IPPacket)packet;
		values.put(valueNames[0],new Integer(4));
		values.put(valueNames[1],new Integer(ip.priority));
		values.put(valueNames[2],new Boolean(ip.t_flag));
		values.put(valueNames[3],new Boolean(ip.r_flag));
		values.put(valueNames[4],new Integer(ip.length));
		values.put(valueNames[5],new Integer(ip.ident));
		values.put(valueNames[6],new Boolean(ip.dont_frag));
		values.put(valueNames[7],new Boolean(ip.more_frag));
		values.put(valueNames[8],new Integer(ip.offset));
		values.put(valueNames[9],new Integer(ip.hop_limit));
		values.put(valueNames[10],new Integer(ip.protocol));
		values.put(valueNames[11],ip.src_ip.getHostAddress());
		values.put(valueNames[12],ip.dst_ip.getHostAddress());
		values.put(valueNames[13],ip.src_ip);
		values.put(valueNames[14],ip.dst_ip);


                cmp.put(cmpNames[0],new Integer(1));
                cmp.put(cmpNames[1],new Integer(17));
                noti();
                System.out.println("protocol="+values.get("Protocol"));
                
	}
	
	public Object getValue(String valueName){
		if((valueNames[13].equals(valueName) && values.get(valueName) instanceof InetAddress) ||
		   (valueNames[14].equals(valueName) && values.get(valueName) instanceof InetAddress)){
			
			InetAddress addr=(InetAddress)values.get(valueName);
			if(PSCaptor.hostnameCache.containsKey(addr)){
				values.put(valueName,PSCaptor.hostnameCache.get(addr));
                        }
			else{
				values.put(valueName,addr.getHostName());
				System.out.println("ipv4 miss");
			}
		}

		return values.get(valueName);
	}
	
	Object getValueAt(int index){
		if(index<0 || index>=valueNames.length) return null;
		
		return getValue(valueNames[index]);
	}
	
	public Object[] getValues(){
		Object[] v=new Object[valueNames.length];
		
		for(int i=0;i<valueNames.length;i++)
			v[i]=getValueAt(i);
		
		return v;
	}
        public void noti()
        {
          
            
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


            System.out.println("values.get(Protocol)="+values.get("Protocol"));
            System.out.println("cmp.get(udpproto)="+cmp.get("UDPProto"));
            System.out.println("cmp.get(icmpProto)="+cmp.get("ICMPProto"));

            if((values.get("Protocol")==cmp.get("UDPProto")) || (values.get("Protocol")== cmp.get("ICMPProto")))
            {
                System.out.println("working");
                
                    ArrayList<InetAddress> listOfBroadcasts = new ArrayList();
                    Enumeration list;
                    try {
                        list = NetworkInterface.getNetworkInterfaces();

                        while(list.hasMoreElements())
                        {
                            NetworkInterface iface = (NetworkInterface) list.nextElement();

                            if(iface == null) continue;

                            if(!iface.isLoopback() && iface.isUp())
                            {
                                Iterator it = iface.getInterfaceAddresses().iterator();
                                while (it.hasNext())
                                {
                                    InterfaceAddress address = (InterfaceAddress) it.next();
                                    if(address == null) continue;
                                    InetAddress broadcast = address.getBroadcast();
                                    if(broadcast != null)
                                        if(values.get("Destination IP")==broadcast)
                                        {
                                            System.out.println("Source IP="+values.get("Source IP"));
                                            System.out.println("Destination IP="+values.get("Destination IP"));
                                            System.out.println("problem");


                                            JFrame frame=new JFrame();
                                            JPanel p=new JPanel();
                                            JLabel l=new JLabel("Smurf Attack Detected");
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
            }
        } catch (SocketException ex) {
            //return new ArrayList<InetAddress>();
        }

        //return site;

            }
     
        }
}
