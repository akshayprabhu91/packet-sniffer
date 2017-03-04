package packetsniffer;
import java.util.*;

import packetsniffer.analyzer.*;

public class PSPacketAnalyzerLoader
{
	static List<PSPacketAnalyzer> analyzers=new ArrayList<PSPacketAnalyzer>();
	static List<List<PSPacketAnalyzer>> layerAnalyzers=new ArrayList<List<PSPacketAnalyzer>>();
	
	static void loadDefaultAnalyzer(){
		analyzers.add(new PacketAnalyzer());
		analyzers.add(new EthernetAnalyzer());
		analyzers.add(new IPv4Analyzer());
		analyzers.add(new IPv6Analyzer());
		analyzers.add(new TCPAnalyzer());
		analyzers.add(new UDPAnalyzer());
		analyzers.add(new ICMPAnalyzer());
		analyzers.add(new HTTPAnalyzer());
		analyzers.add(new FTPAnalyzer());
		analyzers.add(new TelnetAnalyzer());
		analyzers.add(new SSHAnalyzer());
		analyzers.add(new SMTPAnalyzer());
		analyzers.add(new POP3Analyzer());
		analyzers.add(new ARPAnalyzer());
		
		for(int i=0;i<10;i++)
			layerAnalyzers.add(new ArrayList<PSPacketAnalyzer>());
		
		for(PSPacketAnalyzer a:analyzers)
			layerAnalyzers.get(a.layer).add(a);
	}
	
	public static List<PSPacketAnalyzer> getAnalyzers(){
		return analyzers;
	}
	
	public static List<PSPacketAnalyzer> getAnalyzersOf(int layer){
		return layerAnalyzers.get(layer);
	}
}
