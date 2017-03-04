package packetsniffer.ui.graph;
import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;
import java.util.Vector;

public class LineGraph extends JPanel
{
	private String[] labels;
	private Vector values=new Vector();
	
	long maxValue=Long.MIN_VALUE,minValue=Long.MAX_VALUE;
	boolean autoMax,autoMin;
	int marginY=20,marginX=20;
	
	private Color[] colors={
		Color.blue,Color.green,Color.yellow.darker(),Color.red,Color.cyan,Color.pink,Color.orange
	};
	
	public LineGraph(String[] labels){
		this(labels,null,Integer.MAX_VALUE,Integer.MIN_VALUE,true,true);
	}
	
	LineGraph(String[] labels,long[][] values){
		this(labels,values,Integer.MAX_VALUE,Integer.MIN_VALUE,true,true);
	}
	
	LineGraph(String[] labels,long[][] values,long minValue,long maxValue){
		this(labels,values,minValue,maxValue,false,false);
	}
	
	LineGraph(String[] labels,long[][] values,long minValue,long maxValue,boolean autoMin,boolean autoMax){
		this.labels=labels;
		this.autoMax=autoMax;this.autoMin=autoMin;
		this.minValue=minValue;this.maxValue=maxValue;

		if(values!=null){
			for(int i=0;i<values.length;i++){
				this.values.addElement(values[i]);
				
				if(autoMin || autoMax){
					for(int j=0;j<values[i].length;j++){
						if(autoMax && values[i][j]>maxValue) maxValue=values[i][j];
						if(autoMin && values[i][j]<minValue) minValue=values[i][j];
					}
				}
			}
		}
		
		setLayout(new BoxLayout(this,BoxLayout.X_AXIS));
		add(new GraphPane());
		add(new LabelPane());
	}
	
	public void addValue(long[] values){
		this.values.addElement(values);
		
		if(autoMin || autoMax){
			for(int i=0;i<values.length;i++){
				if(autoMax && values[i]>maxValue) maxValue=values[i];
				if(autoMin && values[i]<minValue) minValue=values[i];
			}
		}
		repaint();
	}
	
	public void clear(){
		values.removeAllElements();
		maxValue=Long.MIN_VALUE;minValue=Long.MAX_VALUE;
		repaint();
	}
	
	void setMinValue(int minValue){this.minValue=minValue;}
	void setMaxValue(int maxValue){this.maxValue=maxValue;}
	void setMinValueAutoSet(boolean autoMin){this.autoMin=autoMin;}
	void setMaxValueAutoSet(boolean autoMax){this.autoMax=autoMax;}
	
	private class GraphPane extends JPanel
	{
		public void paintComponent(Graphics g){
			super.paintComponent(g);
			
			setBackground(Color.white);
			if(labels==null || values==null || values.size()==0) return;
			
			//calc font size
			int ylabelw=0;
			for(int i=0;i<4;i++){
				int w=g.getFontMetrics().stringWidth(String.valueOf((double)(maxValue-(maxValue-minValue)*i/4.0)));
				if(w>ylabelw) ylabelw=w;
			}
			
			long h=getHeight()-marginY-marginY,w=getWidth(),h2=maxValue-minValue;
			double d=(double)(w-marginX-marginX)/(values.size()-1.0),x=d+marginX+ylabelw;
			
			//draw X/Y axis
			g.setColor(Color.black);
			//g.drawLine(ylabelw,getHeight()-marginY,getWidth(),getHeight()-marginY);
			g.drawLine(marginX+ylabelw,0,marginX+ylabelw,getHeight());
			g.setColor(Color.gray);
			for(int i=0;i<5;i++){
				int y=marginY+(getHeight()-marginY-marginY)/4*i;
				g.drawLine(marginX+ylabelw,y,getWidth(),y);
				g.drawString(String.valueOf((double)(maxValue-(maxValue-minValue)*i/4.0)),marginX-5,y);
			}
			
			long[] vv=(long[])values.firstElement();
			for(int i=1;i<values.size();i++,x+=d){
				long[] v=(long[])values.elementAt(i);
				
				for(int j=0;j<v.length;j++){
					Color c=colors[j%colors.length];
					for(int k=0;k<j/colors.length;k++) c.darker();
					g.setColor(c);
					
					//((Graphics2D)g).setStroke(new BasicStroke(2.0f));
					//((Graphics2D)g).draw(new Line2D.Double((int)(x-d),h+marginY-(vv[j]-minValue)*h/h2,
					//		(int)x,h+marginY-(v[j]-minValue)*h/h2));
					g.drawLine((int)(x-d),(int)(h+marginY-(vv[j]-minValue)*h/h2),(int)x,(int)(h+marginY-(v[j]-minValue)*h/h2));
				}
				
				vv=v;
			}
		}
	}
	
	private class LabelPane extends JPanel
	{
		LabelPane(){
			setLayout(new BoxLayout(this,BoxLayout.Y_AXIS));
			setBackground(Color.white);
			
			for(int i=0;i<labels.length;i++){
				JPanel cont=new JPanel();
				cont.setLayout(new BoxLayout(cont,BoxLayout.X_AXIS));
				cont.setBackground(Color.white);
				JLabel label=new JLabel(labels[i],SwingConstants.LEFT);
				label.setForeground(Color.black);
				JLabel box=new JLabel("    ");
				box.setOpaque(true);
				
				Color c=colors[i%colors.length];
				for(int j=0;j<i/colors.length;j++) c.darker();
				box.setBackground(c);
				
				cont.add(box);
				cont.add(Box.createRigidArea(new Dimension(5,0)));
				cont.add(label);
				cont.setAlignmentX(0.0f);
				add(cont);
				add(Box.createRigidArea(new Dimension(0,5)));
			}
			
			setBorder(new CompoundBorder(BorderFactory.createLineBorder(Color.black,1),
				new EmptyBorder(10,10,10,10)));
		}
		public Dimension getMinimumSize(){ return new Dimension(50,1); }
	}
	
	public Dimension getPreferredSize(){
		return new Dimension(300,200);
	}

	public static void main(String[] args){
		String[] labels={"layout","box"};
		long[][] data={{1,1},{2,4},{3,2}};

		JFrame f=new JFrame();
		f.addWindowListener(new java.awt.event.WindowAdapter(){
			public void windowClosing(java.awt.event.WindowEvent e){System.exit(0);}
		});
		LineGraph l=new LineGraph(labels,null,0,10);
		f.getContentPane().add(l);
		f.pack();
		f.setVisible(true);
	}
}