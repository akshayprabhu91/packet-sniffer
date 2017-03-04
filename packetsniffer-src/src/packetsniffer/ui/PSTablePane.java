package packetsniffer.ui;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import java.util.*;
import java.util.List;

import packetsniffer.PSCaptor;
import packetsniffer.PSPacketAnalyzerLoader;
import packetsniffer.PacketSniffer;
import packetsniffer.analyzer.PSPacketAnalyzer;
import jpcap.packet.*;

import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import packetsniffer.stat.PSStatisticsTaker;

import packetsniffer.stat.ApplicationProtocolStat;
import packetsniffer.stat.FreeMemStat;
import packetsniffer.stat.PSStatisticsTaker;
import packetsniffer.stat.NetworkProtocolStat;
import packetsniffer.stat.PacketStat;
import packetsniffer.stat.TransportProtocolStat;

public class PSTablePane extends JPanel implements ActionListener,ListSelectionListener,ChangeListener
{
	PSTable table;
	JDTableTree tree;
	JDTableTextArea text;
	PSCaptor captor;
        JPanel jp,j1,j2,j3,j4;
        JPanel graph=new JPanel();
        JTabbedPane graphtab;
        PSStatFrame p;
        JPanel upper=new JPanel();
        JPanel notification=new JPanel();
        JSplitPane mainPane=new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        JLabel label=new JLabel("This space is for notification");

	List<PSPacketAnalyzer> analyzers;
	
	JMenu[] tableViewMenu=new JMenu[4];
   
	PSTablePane(PSCaptor captor){
		this.captor=captor;
		table=new PSTable(this,captor);
		tree=new JDTableTree();
		text=new JDTableTextArea();

                
		
		JSplitPane splitPane=new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		JSplitPane splitPane1=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane splitPane2=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setTopComponent(table);
                splitPane.setBottomComponent(splitPane2);
		splitPane2.setTopComponent(tree);
                splitPane2.setBottomComponent(splitPane1);
		splitPane1.setTopComponent(new JScrollPane(text));
                splitPane1.setBottomComponent(graph);

                graphtab=new JTabbedPane();
                graph.setSize(400,300);
                j1=new JPanel();
                j1.add(new JLabel("here it goes"));


                j1.setVisible(true);

                JPanel j2=new JPanel();
                
                j2.setVisible(true);

                JPanel j3=new JPanel();
                j3.add(new JLabel("third ta is also working properly"));
                j3.setVisible(true);

                JPanel j4=new JPanel();
                j4.add(new JLabel("here we will show whole packet informat"));
                j4.setVisible(true);



                graphtab.addTab("NETWORK",j1);
                graphtab.addTab("TRANSPORT",jp);
                graphtab.addTab("APPLICATION",j3);
                graphtab.addTab("ENTIRE",j4);
                graphtab.setSize(graph.getSize());
                
                
                graph.setLayout(new BorderLayout());
                graph.add(graphtab,BorderLayout.CENTER);
                graph.setSize(2800,800);
                j2.add(new JLabel("its workingvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"));


                mainPane.setTopComponent(splitPane);
                mainPane.setBottomComponent(notification);

		mainPane.setDividerLocation(500);
		splitPane.setDividerLocation(200);
		splitPane2.setDividerLocation(200);
                splitPane1.setDividerLocation(400);

                //notification.add(label);
                notification.setVisible(true);
                
		tableViewMenu[0]=new JMenu("Datalink Layer");
		tableViewMenu[1]=new JMenu("Network Layer");
		tableViewMenu[2]=new JMenu("Transport Layer");
		tableViewMenu[3]=new JMenu("Application Layer");
		analyzers=PSPacketAnalyzerLoader.getAnalyzers();
		JMenuItem item,subitem;
		
		for(int i=0;i<analyzers.size();i++){
			PSPacketAnalyzer analyzer=analyzers.get(i);
			item=new JMenu(analyzer.getProtocolName());
			String[] valueNames=analyzer.getValueNames();
			if(valueNames==null) continue;
			for(int j=0;j<valueNames.length;j++){
				subitem=new JCheckBoxMenuItem(valueNames[j]);
				subitem.setActionCommand("TableView"+i);
				subitem.addActionListener(this);
				item.add(subitem);
			}
			tableViewMenu[analyzer.layer].add(item);
		}
                
                graphtab.addChangeListener(this);
		setLayout(new BorderLayout());
		add(mainPane,BorderLayout.CENTER);

		loadProperty();
		setSize(400,200);
                graphtab.setSize(2800,800);
                System.out.println("graphtab="+graphtab.getSize());
                System.out.println("graph="+graph.getSize());
	
                
        }
   
                public void stateChanged(ChangeEvent changeEvent) {
                JTabbedPane sourceTabbedPane = (JTabbedPane) changeEvent.getSource();
                int index = sourceTabbedPane.getSelectedIndex();
                String changedTab=sourceTabbedPane.getTitleAt(index);
                if(changedTab=="TRANSPORT")
                {
                    System.out.println("transport");
                    jp=captor.addCumulativeStatFrame(new TransportProtocolStat());
                    //graphtab.addTab("NETWORK",jp);
                    graphtab.setComponentAt(1,jp);
                    //p=(PSStatFrame)jp;
                    //p.PSStatFrameUpdater.start();
                    //p.fireUpdate();
                    //p.repaint();
                  
                }
                else if(changedTab=="NETWORK")
                {
                    System.out.println("network");
                    j1=captor.addCumulativeStatFrame(new NetworkProtocolStat());
                    graphtab.setComponentAt(0,j1);
                }
                else if(changedTab=="APPLICATION")
                {
                    System.out.println("application");
                    j2=captor.addCumulativeStatFrame(new ApplicationProtocolStat());
                    graphtab.setComponentAt(2,j2);
                }
                else if(changedTab=="ENTIRE")
                {
                    System.out.println("entire");
                    j3=captor.addCumulativeStatFrame(new PacketStat());
                    graphtab.setComponentAt(3,j3);
                }
      }
    
    
	
	void fireTableChanged(){
		table.fireTableChanged();
	}
	
	void clear(){
		table.clear();
	}
	
	public void setTableViewMenu(JMenu menu){
		menu.add(tableViewMenu[0]);
		menu.add(tableViewMenu[1]);
		menu.add(tableViewMenu[2]);
		menu.add(tableViewMenu[3]);
	}
	
	public void actionPerformed(ActionEvent evt){
		String cmd=evt.getActionCommand();
		
		if(cmd.startsWith("TableView")){
			int index=Integer.parseInt(cmd.substring(9));
			JCheckBoxMenuItem item=(JCheckBoxMenuItem)evt.getSource();
			table.setTableView(analyzers.get(index),item.getText(),item.isSelected());
		}
	}
	
	public void valueChanged(ListSelectionEvent evt){
		if(evt.getValueIsAdjusting()) return;
		
		int index=((ListSelectionModel)evt.getSource()).getMinSelectionIndex();
		if(index>=0){
			Packet p=(Packet)captor.getPackets().get(table.sorter.getOriginalIndex(index));
			tree.analyzePacket(p);
			text.showPacket(p);
		}
	}
	
	void loadProperty(){
		//get all menus
		Component[] menus=new Component[analyzers.size()];
		int k=0;
		for(int j=0;j<tableViewMenu[0].getMenuComponents().length;j++)
			menus[k++]=tableViewMenu[0].getMenuComponents()[j];
		for(int j=0;j<tableViewMenu[1].getMenuComponents().length;j++)
			menus[k++]=tableViewMenu[1].getMenuComponents()[j];
		for(int j=0;j<tableViewMenu[2].getMenuComponents().length;j++)
			menus[k++]=tableViewMenu[2].getMenuComponents()[j];
		for(int j=0;j<tableViewMenu[3].getMenuComponents().length;j++)
			menus[k++]=tableViewMenu[3].getMenuComponents()[j];
		
		//load ptoperty
		StringTokenizer status=new StringTokenizer(PacketSniffer.preferences.get("TableView",
				"Ethernet Frame:Source MAC,Ethernet Frame:Destination MAC,IPv4:Source IP,IPv4:Destination IP"),",");
		
		while(status.hasMoreTokens()){
			StringTokenizer s=new StringTokenizer(status.nextToken(),":");
			if(s.countTokens()==2){
				String name=s.nextToken(),valueName=s.nextToken();
				//for(int i=0;i<analyzers.length;i++)
					//if(analyzers[i].getProtocolName().equals(name)){
				for(int i=0;i<menus.length;i++){
					if(((JMenu)menus[i]).getText()==null || name==null) continue;
					if(((JMenu)menus[i]).getText().equals(name)){
						Component[] vn=((JMenu)menus[i]).getMenuComponents();
						//table.setTableView(analyzers[i],n,true);
						for(int j=0;j<vn.length;j++)
							if(valueName.equals(((JCheckBoxMenuItem)vn[j]).getText())){
								((JCheckBoxMenuItem)vn[j]).setState(true);
								break;
							}
						break;
					}
				}
				
				for(PSPacketAnalyzer analyzer:analyzers)
					if(analyzer.getProtocolName().equals(name)){
						table.setTableView(analyzer,valueName,true);
						break;
					}
			}
		}
	}
	
	void saveProperty(){
		String[] viewStatus=table.getTableViewStatus();
		if(viewStatus.length>0){
			StringBuffer buf=new StringBuffer(viewStatus[0]);
			for(int i=1;i<viewStatus.length;i++)
				buf.append(","+viewStatus[i]);
			//JpcapDumper.JDProperty.setProperty("TableView",buf.toString());
			PacketSniffer.preferences.put("TableView",buf.toString());
		}
	}

        //abstract void fireUpdate();
	//public abstract void addPacket(Packet p);
	//public abstract void clear();

	public void startUpdating(){
		PSStatFrameUpdate.setRepeats(true);
		PSStatFrameUpdate.start();
	}

	public void stopUpdating(){
		PSStatFrameUpdate.stop();
		PSStatFrameUpdate.setRepeats(false);
		PSStatFrameUpdate.start();
	}
        javax.swing.Timer PSStatFrameUpdate=new javax.swing.Timer(500,new ActionListener(){
		public void actionPerformed(ActionEvent evt){
			//fireUpdate();
			repaint();
		}
	});
        
        
                
}
