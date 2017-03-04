package packetsniffer.analyzer;
import jpcap.packet.*;

public class FTPAnalyzer extends PSPacketAnalyzer
{
	public FTPAnalyzer(){
		layer=APPLICATION_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		if(p instanceof TCPPacket &&
		   (((TCPPacket)p).src_port==20 || ((TCPPacket)p).dst_port==20 ||
		    ((TCPPacket)p).src_port==21 || ((TCPPacket)p).dst_port==21))
			return true;
		else return false;
	}
	
	public String getProtocolName(){
		return "FTP";
	}
	
	public String[] getValueNames(){return null;}
	
	public void analyze(Packet p){}
	
	public Object getValue(String s){ return null; }
	public Object getValueAt(int i){ return null; }
	public Object[] getValues(){ return null; }
}
