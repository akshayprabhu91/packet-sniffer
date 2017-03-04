package packetsniffer;
import java.util.*;

import packetsniffer.stat.ApplicationProtocolStat;
import packetsniffer.stat.FreeMemStat;
import packetsniffer.stat.PSStatisticsTaker;
import packetsniffer.stat.NetworkProtocolStat;
import packetsniffer.stat.PacketStat;
import packetsniffer.stat.TransportProtocolStat;

public class PSStatisticsTakerLoader
{
	static ArrayList<PSStatisticsTaker> stakers=new ArrayList<PSStatisticsTaker>();
	
	static void loadStatisticsTaker(){
		stakers.add(new PacketStat());
		stakers.add(new NetworkProtocolStat());
		stakers.add(new TransportProtocolStat());
		stakers.add(new ApplicationProtocolStat());
		stakers.add(new FreeMemStat());
	}
	
	public static List<PSStatisticsTaker> getStatisticsTakers(){
		return stakers;
	}
	
	public static PSStatisticsTaker getStatisticsTakerAt(int index){
		return stakers.get(index);
	}
}
