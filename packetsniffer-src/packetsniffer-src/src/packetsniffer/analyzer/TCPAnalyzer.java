package packetsniffer.analyzer;
import jpcap.packet.*;
import java.util.*;

public class TCPAnalyzer extends PSPacketAnalyzer
{
	private static final String[] valueNames={
		"Source Port",
		"Destination Port",
		"Sequence Number",
		"Ack Number",
		"URG Flag",
		"ACK Flag",
		"PSH Flag",
		"RST Flag",
		"SYN Flag",
		"FIN Flag",
		"Window Size"};
	Hashtable values=new Hashtable();
	
	public TCPAnalyzer(){
		layer=TRANSPORT_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		return (p instanceof TCPPacket);
	}
	
	public String getProtocolName(){
		return "TCP";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet p){
		values.clear();
		if(!isAnalyzable(p)) return;
		TCPPacket tcp=(TCPPacket)p;
		values.put(valueNames[0],new Integer(tcp.src_port));
		values.put(valueNames[1],new Integer(tcp.dst_port));
		values.put(valueNames[2],new Long(tcp.sequence));
		values.put(valueNames[3],new Long(tcp.ack_num));
		values.put(valueNames[4],new Boolean(tcp.urg));
		values.put(valueNames[5],new Boolean(tcp.ack));
		values.put(valueNames[6],new Boolean(tcp.psh));
		values.put(valueNames[7],new Boolean(tcp.rst));
		values.put(valueNames[8],new Boolean(tcp.syn));
		values.put(valueNames[9],new Boolean(tcp.fin));
		values.put(valueNames[10],new Integer(tcp.window));
                
                noti();
	}
	
	public Object getValue(String valueName){
		return values.get(valueName);
	}
	
	Object getValueAt(int index){
		if(index<0 || index>=valueNames.length) return null;
		return values.get(valueNames[index]);
	}
	
	public Object[] getValues(){
		Object[] v=new Object[valueNames.length];
		
		for(int i=0;i<valueNames.length;i++)
			v[i]=values.get(valueNames[i]);
		
		return v;
	}
        public void noti()
        {
            System.out.println("urgent flag="+values.get("URG Flag"));
            
            if(("139".equals(values.get("Destination Port"))) && "true".equals(
                values.get("URG Flag")))
            {
               System.out.println("its true");
            }
        }
}
