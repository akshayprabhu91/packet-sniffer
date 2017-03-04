package packetsniffer.analyzer;
import jpcap.packet.*;
import java.util.*;
import java.io.*;

public class HTTPAnalyzer extends PSPacketAnalyzer
{
	private static final String[] valueNames={
		"Method",
		"Header"
	};
	String method;
	Vector headers=new Vector();
	
	public HTTPAnalyzer(){
		layer=APPLICATION_LAYER;
	}
	
	public boolean isAnalyzable(Packet p){
		if(p instanceof TCPPacket &&
		   (((TCPPacket)p).src_port==80 || ((TCPPacket)p).dst_port==80))
			return true;
		else return false;
	}
	
	public String getProtocolName(){
		return "HTTP";
	}
	
	public String[] getValueNames(){
		return valueNames;
	}
	
	public void analyze(Packet p){
		method="";
		headers.removeAllElements();
		if(!isAnalyzable(p)) return;
		
		try{
			BufferedReader in=new BufferedReader(new StringReader(new String(p.data)));
			
			method=in.readLine();
			if(method==null || method.indexOf("HTTP")==-1){
				// this packet doesn't contain HTTP header
				method="Not HTTP Header";
				return;
			}
			
			String l;
			//read headers
			while((l=in.readLine()).length()>0)
				headers.addElement(l);
		}catch(IOException e){}
	}
	
	public Object getValue(String valueName){
		if(valueNames[0].equals(valueName)) return method;
		if(valueNames[1].equals(valueName)) return headers;
		return null;
	}
	
	Object getValueAt(int index){
		if(index==0) return method;
		if(index==1) return headers;
		return null;
	}
	
	public Object[] getValues(){
		Object[] values=new Object[2];
		values[0]=method;
		values[1]=headers;
		
		return values;
	}
}
