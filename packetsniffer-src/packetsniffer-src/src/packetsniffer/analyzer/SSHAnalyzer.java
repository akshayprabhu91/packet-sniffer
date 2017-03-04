package packetsniffer.analyzer;
import jpcap.packet.*;

public class SSHAnalyzer extends PSPacketAnalyzer
{
	public SSHAnalyzer(){
		layer=APPLICATION_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		if(p instanceof TCPPacket &&
		   (((TCPPacket)p).src_port==22 || ((TCPPacket)p).dst_port==22))
			return true;
		else return false;
	}
	
	public String getProtocolName(){
		return "SSH";
	}
	
	public String[] getValueNames(){return null;}
	
	public void analyze(Packet p){}
	
	public Object getValue(String s){ return null; }
	public Object getValueAt(int i){ return null; }
	public Object[] getValues(){ return null; }
}
