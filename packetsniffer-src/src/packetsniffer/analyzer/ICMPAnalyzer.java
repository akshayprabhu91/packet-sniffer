package packetsniffer.analyzer;
import jpcap.packet.*;
import java.util.*;

public class ICMPAnalyzer extends PSPacketAnalyzer
{
	private static final String[] valueNames={
		"Type",
		"Code",
		"ID",
		"Sequence",
		"Redirect Address",
		"Address Mask",
		"Original Timestamp",
		"Receive Timestamp",
		"Transmission Timestamp"
	};
	
	private static final String[] typeNames={
		"Echo Reply(0)",
		"Unknown(1)",
		"Unknown(2)",
		"Destination Unreachable(3)",
		"Source Quench(4)",
		"Redirect(5)",
		"Unknown(6)",
		"Unknown(7)",
		"Echo(8)",
		"Unknown(9)",
		"Unknown(10)",
		"Time Exceeded(11)",
		"Parameter Problem(12)",
		"Timestamp(13)",
		"Timestamp Reply(14)",
		"Unknown(15)",
		"Unknown(16)",
		"Address Mask Request(17)",
		"Address Mask Reply(18)"
	};
	
	private Hashtable values=new Hashtable();
	
	public ICMPAnalyzer(){
		layer=TRANSPORT_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		return (p instanceof ICMPPacket);
	}
	
	public String getProtocolName(){
		return "ICMP";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet p){
		if(!isAnalyzable(p)) return;
		values.clear();
		
		ICMPPacket icmp=(ICMPPacket)p;
		if(icmp.type>=typeNames.length){
			values.put(valueNames[0],String.valueOf(icmp.type));
		}else{
			values.put(valueNames[0],typeNames[icmp.type]);
		}
		values.put(valueNames[1],new Integer(icmp.code));
		
		if(icmp.type==0 || icmp.type==8 || (icmp.type>=13 && icmp.type<=18)){
			values.put(valueNames[2],new Integer(icmp.id));
			values.put(valueNames[3],new Integer(icmp.seq));
		}
		
		if(icmp.type==5)
			values.put(valueNames[4],icmp.redir_ip);
		
		if(icmp.type==17 || icmp.type==18)
			values.put(valueNames[5],(icmp.subnetmask>>12)+"."+
			                         ((icmp.subnetmask>>8)&0xff)+"."+
			                         ((icmp.subnetmask>>4)&0xff)+"."+
			                         (icmp.subnetmask&0xff)+".");
		
		if(icmp.type==13 || icmp.type==14){
			values.put(valueNames[6],new Long(icmp.orig_timestamp));
			values.put(valueNames[7],new Long(icmp.recv_timestamp));
			values.put(valueNames[8],new Long(icmp.trans_timestamp));
		}
	}
	
	public Object getValue(String valueName){
		return values.get(valueName);
	}
	
	public Object getValueAt(int index){
		if(index<0 || index>=valueNames.length) return null;
		return values.get(valueNames[index]);
	}
	
	public Object[] getValues(){
		Object[] v=new Object[valueNames.length];
		
		for(int i=0;i<valueNames.length;i++)
			v[i]=values.get(valueNames[i]);
		
		return v;
	}
}
