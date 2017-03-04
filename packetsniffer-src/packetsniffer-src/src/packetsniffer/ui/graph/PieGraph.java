package packetsniffer.ui.graph;
import java.awt.*;
import javax.swing.*;

public class PieGraph extends JPanel
{
	private String[] labels;
	private long[] values;
	
	private Color[] colors={
		Color.blue,Color.green,Color.yellow,Color.red,Color.cyan,Color.pink,Color.orange
	};
	
	public PieGraph(String[] labels,long[] values){
		this.labels=labels;
		this.values=values;
	}
	
	public void changeValue(long[] values){
		this.values=values;
		repaint();
	}
	
	public void paintComponent(Graphics g){
		super.paintComponent(g);
		
		if(labels==null || values==null) return;
		
		int r=Math.min(getWidth(),getHeight())/2-20;
		int x=getWidth()/2,y=getHeight()/2;
		int sum=0;
		for(int i=0;i<values.length;i++) sum+=values[i];
		
		double startAngle=90.0;
		for(int i=0;i<values.length;i++){
			if(values[i]==0) continue;
			double angle=(double)values[i]*360.0/(double)sum;
			
			Color c=colors[i%colors.length];
			for(int j=0;j<i/colors.length;j++) c.darker();
			g.setColor(c);
			g.fillArc(x-r,y-r,r*2,r*2,(int)startAngle,(int)-angle);
			
			startAngle-=angle;
		}

		startAngle=90.0;
		for(int i=0;i<values.length;i++){
			if(values[i]==0) continue;
			double angle=values[i]*360.0/sum;

			int sx=(int)(Math.cos(2*Math.PI*(startAngle-angle/2)/360)*(double)(r+10));
			int sy=(int)(Math.sin(2*Math.PI*(startAngle-angle/2)/360)*(double)(r+10));
			g.setColor(Color.black);
			g.drawString(labels[i],x+sx,y-sy);
			
			startAngle-=angle;
		}
	}
	
	public Dimension getPreferredSize(){
		return new Dimension(100,100);
	}
}
