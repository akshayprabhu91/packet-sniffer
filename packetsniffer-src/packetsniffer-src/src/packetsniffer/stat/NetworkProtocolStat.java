package packetsniffer.stat;
import jpcap.packet.*;
import java.util.*;

import packetsniffer.PSPacketAnalyzerLoader;
import packetsniffer.analyzer.PSPacketAnalyzer;

public class NetworkProtocolStat extends PSStatisticsTaker
{
	List<PSPacketAnalyzer> analyzers;
	long[] numOfPs;
	long totalPs;
	long[] sizeOfPs;
	long totalSize;
	String[] labels;
	static final String[] types={"# of packets","% of packets","total packet size","% of size"};
	
	public NetworkProtocolStat(){
		analyzers=PSPacketAnalyzerLoader.getAnalyzersOf(PSPacketAnalyzer.NETWORK_LAYER);
		numOfPs=new long[analyzers.size()+1];
		sizeOfPs=new long[analyzers.size()+1];

		labels=new String[analyzers.size()+1];
		for(int i=0;i<analyzers.size();i++)
			labels[i]=analyzers.get(i).getProtocolName();
		labels[analyzers.size()]="Other";
	}
	
	public String getName(){
		return "Netowrk Layer Protocol Ratio";
	}
	
	public void analyze(List<Packet> packets){
		for(int i=0;i<packets.size();i++){
			Packet p=(Packet)packets.get(i);
			totalPs++;
			totalSize+=p.len;
			
			boolean flag=false;
			for(int j=0;j<analyzers.size();j++)
				if(analyzers.get(j).isAnalyzable(p)){
					numOfPs[j]++;
					totalPs++;
					sizeOfPs[j]+=p.len;
					flag=true;
					break;
				}
			if(!flag){
				numOfPs[numOfPs.length-1]++;
				sizeOfPs[sizeOfPs.length-1]+=p.len;
			}
		}
	}
	
	public void addPacket(Packet p){
		boolean flag=false;
		totalPs++;
		totalSize+=p.len;
		for(int j=0;j<analyzers.size();j++)
			if(analyzers.get(j).isAnalyzable(p)){
				numOfPs[j]++;
				sizeOfPs[j]+=p.len;
				flag=true;
				break;
			}
		if(!flag){
			numOfPs[numOfPs.length-1]++;
			sizeOfPs[sizeOfPs.length-1]+=p.len;
		}
	}
	
	public String[] getLabels(){
		return labels;
	}
	
	public String[] getStatTypes(){
		return types;
	}
	
	public long[] getValues(int index){
		switch(index){
			case 0: //# of packets
				if(numOfPs==null) return new long[0];
				return numOfPs;
			case 1: //% of packets
				long[] percents=new long[numOfPs.length];
				if(totalPs==0) return percents;
				for(int i=0;i<numOfPs.length;i++)
					percents[i]=numOfPs[i]*100/totalPs;
				return percents;
			case 2: //total packet size
				if(sizeOfPs==null) return new long[0];
				return sizeOfPs;
			case 3: //% of size
				long[] percents2=new long[sizeOfPs.length];
				if(totalSize==0) return percents2;
				for(int i=0;i<sizeOfPs.length;i++)
					percents2[i]=sizeOfPs[i]*100/totalSize;
				return percents2;
			default:
				return null;
		}
	}
	/*
	String[] getTableLabels(){
		String[] ls=new String[labels.length+1];
		ls[0]=new String();
		System.arraycopy(labels,0,ls,1,labels.length);
		
		return ls;
	}
	
	Object[][] getTableValues(){
		if(numOfPs==null) return new Object[0][0];
		long sum=0;
		Object[][] obj=new Object[4][labels.length+1];
		
		obj[0][0]="# of packets";
		for(int i=0;i<numOfPs.length;i++){
			obj[0][i+1]=new Long(numOfPs[i]);
			sum+=numOfPs[i];
		}
		
		obj[1][0]="% of packet #";
		for(int i=0;i<numOfPs.length;i++){
			if(sum==0) obj[1][i+1]=new Integer(0);
			else obj[1][i+1]=new Integer(numOfPs[i]*100/(int)sum);
		}
		
		sum=0;
		obj[2][0]="size of packets";
		for(int i=0;i<sizeOfPs.length;i++){
			obj[2][i+1]=new Long(sizeOfPs[i]);
			sum+=sizeOfPs[i];
		}
		
		obj[3][0]="% of size";
		for(int i=0;i<sizeOfPs.length;i++){
			if(sum==0) obj[3][i+1]=new Long(0);
			else obj[3][i+1]=new Long(sizeOfPs[i]*100/sum);
		}
		
		return obj;
	}
	*/
	
	public void clear(){
		numOfPs=new long[analyzers.size()+1];
		sizeOfPs=new long[analyzers.size()+1];
		totalPs=0;
		totalSize=0;
	}
}
