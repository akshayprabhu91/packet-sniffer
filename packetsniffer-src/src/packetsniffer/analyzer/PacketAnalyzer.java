package packetsniffer.analyzer;
import jpcap.packet.*;

public class PacketAnalyzer extends PSPacketAnalyzer
{
	private static final String[] valueNames={"Captured Time","Captured Length"};
	private Packet packet;
	
	public boolean isAnalyzable(Packet packet){
		return true;
	}
	
	public String getProtocolName(){
		return "Packet Information";
	}
	
	public String[] getValueNames(){
		  return valueNames;
	}
	
	public void analyze(Packet p){
		packet=p;
	}
	
	public Object getValue(String name){
		if(name.equals(valueNames[0]))
			return new java.util.Date(packet.sec*1000+packet.usec/1000).toString();
		else if(name.equals(valueNames[1]))
			return new Integer(packet.caplen);
		else return null;
	}
	
	Object getValueAt(int index){
		switch(index){
			case 0: return new java.util.Date(packet.sec*1000+packet.usec/1000).toString();
			case 1: return new Integer(packet.caplen);
			default: return null;
		}
	}
	
	public Object[] getValues(){
		Object[] v=new Object[2];
		v[0]=new java.util.Date(packet.sec*1000+packet.usec/1000).toString();
		v[1]=new Integer(packet.caplen);
		
		return v;
	}
}