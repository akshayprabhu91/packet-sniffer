package packetsniffer.ui;
import jpcap.packet.*;
import java.awt.*;
import java.util.*;
import java.util.List;

import packetsniffer.stat.PSStatisticsTaker;
import packetsniffer.ui.graph.LineGraph;

public class PSContinuousStatFrame extends PSStatFrame
{
	LineGraph lineGraph;
	
	PSStatisticsTaker staker;
	int statType;
	boolean drawTimescale; //true-> time, false->packet#
	int count,currentCount=0;
	long currentSec=0;
	
	public static PSContinuousStatFrame openWindow(List<Packet> packets,PSStatisticsTaker staker){
		PSContinuousStatFrame frame=new PSContinuousStatFrame(packets,5,true,staker,0);
		frame.setVisible(true);
		return frame;
	}
	
	PSContinuousStatFrame(List<Packet> packets,int count,boolean isTime,PSStatisticsTaker staker,int type){
		super(staker.getName()+" ["+staker.getStatTypes()[type]+"]");
		this.staker=staker;
		this.drawTimescale=isTime;this.count=count;
		statType=type;
		
		lineGraph=new LineGraph(staker.getLabels());
		
		//getContentPane().setLayout(new BorderLayout());
		//getContentPane().add(lineGraph,BorderLayout.CENTER);
		setSize(400,400);
		
		if(packets==null || packets.size()==0) return;
		
		Iterator it=packets.iterator();
		currentSec=((Packet)packets.get(0)).sec;
		currentCount=0;
		int index=0;
		if(isTime){
			while(index<packets.size()){
				Packet p=(Packet)packets.get(index++);
				
				while(index<packets.size() && p.sec-currentSec<=count){
					staker.addPacket(p);
					p=(Packet)packets.get(index++);
				}
				if(index==packets.size()) break;
				currentSec+=count;
				index--;
				lineGraph.addValue(staker.getValues(type));
				staker.clear();
			}
		}else{
			while(it.hasNext()){
				for(int i=0;it.hasNext() && i<count;i++,currentCount++)
					staker.addPacket((Packet)it.next());
				if(!it.hasNext()) break;
				currentCount=0;
				lineGraph.addValue(staker.getValues(type));
				staker.clear();
			}
		}
	}
	
	public void addPacket(Packet p){
		staker.addPacket(p);
		if(drawTimescale){
			if(currentSec==0) currentSec=p.sec;
			if(p.sec-currentSec>count){
				lineGraph.addValue(staker.getValues(statType));
				staker.clear();
				currentSec+=count;
				if(p.sec-currentSec>count)
					for(long s=p.sec-currentSec-count;s>count;s-=count){
						lineGraph.addValue(staker.getValues(statType));
					}
			}
		}else{
			currentCount++;
			if(currentCount==count){
				lineGraph.addValue(staker.getValues(statType));
				staker.clear();
				currentCount=0;
			}
		}
	}
	
	public void clear(){
		currentCount=0;
		currentSec=0;
		lineGraph.clear();
	}

	void fireUpdate(){
		repaint();
	}
}
