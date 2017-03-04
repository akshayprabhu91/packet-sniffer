    package packetsniffer.ui;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import packetsniffer.PSCaptor;
import packetsniffer.PSStatisticsTakerLoader;
import packetsniffer.PacketSniffer;
import packetsniffer.stat.PSStatisticsTaker;

public class PSFrame extends JFrame implements ActionListener
{
	public PSCaptor captor;
	
	JLabel statusLabel;
	JMenuItem open,save,start,stop,item;
	JMenu statMenu,menu;
	JButton openButton,saveButton,captureButton,stopButton;
	
	public PSTablePane tablePane;

	public static PSFrame openNewWindow(PSCaptor captor){
		PSFrame frame=new PSFrame(captor);
		frame.setVisible(true);
		
		return frame;
	}

	public PSFrame(PSCaptor captor){
		this.captor=captor;
		tablePane=new PSTablePane(captor);
		captor.setPSFrame(this);
		
		setTitle("Packet Sniffer");

		// Create Menu
		JMenuBar menuBar=new JMenuBar();
		setJMenuBar(menuBar);
		
		//System Menu
		JMenu system=new JMenu("System");
		menuBar.add(system);

                JMenu capture=new JMenu("Capture");
		capture.setActionCommand("Capture");
		capture.addActionListener(this);
		system.add(capture);

                start=new JMenuItem("Start");
                start.setActionCommand("Start");
                start.addActionListener(this);
                capture.add(start);

                stop=new JMenuItem("Stop");
                stop.setActionCommand("Stop");
                stop.addActionListener(this);
                capture.add(stop);


                JMenuItem filter=new JMenuItem("Filter");
		filter.setActionCommand("Filter");
		filter.addActionListener(this);
		system.add(filter);

		JMenuItem newwin=new JMenuItem("New Window");
		newwin.setActionCommand("NewWin");
		newwin.addActionListener(this);
		system.add(newwin);

		JMenuItem exit=new JMenuItem("Exit");
		exit.setActionCommand("Exit");
		exit.addActionListener(this);
		system.add(exit);
		
		//File Menu
		JMenu file=new JMenu("File");
		menuBar.add(file);

		open=new JMenuItem("Open");
		open.setIcon(getImageIcon("/image/open.gif"));
		open.setActionCommand("Open");
		open.addActionListener(this);
		file.add(open);

                save=new JMenuItem("Save");
		save.setIcon(getImageIcon("/image/save.gif"));
		save.setActionCommand("Save");
		save.addActionListener(this);
		save.setEnabled(false);
		file.add(save);

		//Capture Menu
		//menu=new JMenu("Capture");
		//menuBar.add(menu);
		//captureMenu=new JMenuItem("Start");
		//captureMenu.setIcon(getImageIcon("/image/capture.gif"));
		//captureMenu.setActionCommand("Start");
		//captureMenu.addActionListener(this);
		//menu.add(captureMenu);
		//stopMenu=new JMenuItem("Stop");
		//stopMenu.setIcon(getImageIcon("/image/stopcap.gif"));
		//stopMenu.setActionCommand("Stop");
		//stopMenu.addActionListener(this);
		//stopMenu.setEnabled(false);
		//menu.add(stopMenu);
		
		//Stat Menu
		statMenu=new JMenu("Statistics");
		menuBar.add(statMenu);
		menu=new JMenu("Cumulative");
		statMenu.add(menu);
		java.util.List<PSStatisticsTaker> stakers=PSStatisticsTakerLoader.getStatisticsTakers();
		for(int i=0;i<stakers.size();i++){
			item=new JMenuItem(stakers.get(i).getName());
			item.setActionCommand("CUMSTAT"+i);
			item.addActionListener(this);
			menu.add(item);
		}
		menu=new JMenu("Continuous");
		statMenu.add(menu);
                //for(int i=0;i<stakers.size();i++){
			//item=new JMenuItem(stakers.get(i).getName());
			//item.setActionCommand("CONSTAT"+i);
			//item.addActionListener(this);
			//menu.add(item);
		//}

		//View menu
		//JMenu view=new JMenu("View");
		//menuBar.add(view);
		//tablePane.setTableViewMenu(view);
		
		//L&F Menu
		/*menu=new JMenu("Look&Feel");
		menuBar.add(menu);
		item=createLaFMenuItem("Metal","javax.swing.plaf.metal.MetalLookAndFeel");
		menu.add(item);
		item.setSelected(true);
		menu.add(createLaFMenuItem("Windows","com.sun.java.swing.plaf.windows.WindowsLookAndFeel"));
		menu.add(createLaFMenuItem("Motif","com.sun.java.swing.plaf.motif.MotifLookAndFeel"));
		menu.add(createLaFMenuItem("Mac","com.sun.java.swing.plaf.mac.MacLookAndFeel"));*/
		
		
		//Create Toolbar
		JToolBar toolbar=new JToolBar();
		toolbar.setFloatable(false);
		openButton=new JButton(getImageIcon("/image/open.gif"));
		openButton.setActionCommand("Open");
		openButton.addActionListener(this);
		toolbar.add(openButton);
		saveButton=new JButton(getImageIcon("/image/save.gif"));
		saveButton.setActionCommand("Save");
		saveButton.addActionListener(this);
		saveButton.setEnabled(false);
		toolbar.add(saveButton);
		toolbar.addSeparator();
		captureButton=new JButton(getImageIcon("/image/capture.gif"));
		captureButton.setActionCommand("Start");
		captureButton.addActionListener(this);
		toolbar.add(captureButton);
		stopButton=new JButton(getImageIcon("/image/stopcap.gif"));
		stopButton.setActionCommand("Stop");
		stopButton.addActionListener(this);
		stopButton.setEnabled(false);
		toolbar.add(stopButton);
		
		statusLabel=new JLabel("Packet Sniffer started.");
		
		getContentPane().setLayout(new BorderLayout());
		//getContentPane().add(desktop,BorderLayout.CENTER);
		getContentPane().add(statusLabel,BorderLayout.SOUTH);
		getContentPane().add(tablePane,BorderLayout.CENTER);
		getContentPane().add(toolbar,BorderLayout.NORTH);
		
		addWindowListener(new WindowAdapter(){
			public void windowClosing(WindowEvent evt){
				saveProperty();
				PacketSniffer.closeWindow((PSFrame)evt.getSource());
			}
		});
		
		loadProperty();
		//pack();
	}
	
	public void actionPerformed(ActionEvent evt){
		String cmd=evt.getActionCommand();
		
		if(cmd.equals("Open")){
			captor.loadPacketsFromFile();
		}else if(cmd.equals("Save")){
			captor.saveToFile();
		}else if(cmd.equals("NewWin")){
			PacketSniffer.openNewWindow();
                }else if(cmd.equals("Filter")){
                        PacketSniffer.openNewWindow();
                        captor.capturePacketsFromDevice();
		}else if(cmd.equals("Exit")){
			saveProperty();
			System.exit(0);
		}else if(cmd.equals("Start")){
			captor.capturePacketsFromDevice();
		}else if(cmd.equals("Stop")){
			captor.stopCapture();
		}else if(cmd.startsWith("CUMSTAT")){
			int index=Integer.parseInt(cmd.substring(7));
			captor.addCumulativeStatFrame(PSStatisticsTakerLoader.getStatisticsTakerAt(index));
		}else if(cmd.startsWith("CONSTAT")){
			int index=Integer.parseInt(cmd.substring(7));
			captor.addContinuousStatFrame(PSStatisticsTakerLoader.getStatisticsTakerAt(index));
		/*}else if(cmd.startsWith("LaF")){
			try{
				UIManager.setLookAndFeel(cmd.substring(3));
				SwingUtilities.updateComponentTreeUI(this);
				SwingUtilities.updateComponentTreeUI(JpcapDumper.chooser);
			}catch(Exception e){}*/
		}
	}
	
	public void clear(){
		tablePane.clear();
	}
	/*void initInternalFrames(){
		packets.removeAllElements();
		totalPacketCount=0;
		tableFrame.clear();

		if(sframes!=null)
			for(int i=0;i<sframes.length;i++)
				if(sframes[i]!=null) sframes[i].clear();
	}*/

	public void startUpdating(){
		JDFrameUpdater.setRepeats(true);
		JDFrameUpdater.start();
	}
	
	public void stopUpdating(){
		JDFrameUpdater.stop();
		JDFrameUpdater.setRepeats(false);
		JDFrameUpdater.start();
	}

	javax.swing.Timer JDFrameUpdater=new javax.swing.Timer(500,new ActionListener(){
		public void actionPerformed(ActionEvent evt){
			tablePane.fireTableChanged();
			statusLabel.setText("Captured "+captor.getPackets().size()+" packets.");

			repaint();
		}
	});

	void loadProperty(){
		setSize(Integer.parseInt(PacketSniffer.preferences.get("WinWidth","640")),
		        Integer.parseInt(PacketSniffer.preferences.get("WinHeight","480")));
		setLocation(Integer.parseInt(PacketSniffer.preferences.get("WinX","0")),
			Integer.parseInt(PacketSniffer.preferences.get("WinY","0")));
	}
	
	void saveProperty(){
		//JpcapDumper.JDProperty.setProperty("WinWidth",String.valueOf(getBounds().width));
		//JpcapDumper.JDProperty.setProperty("WinHeight",String.valueOf(getBounds().height));
		PacketSniffer.preferences.put("WinWidth",String.valueOf(getBounds().width));
		PacketSniffer.preferences.put("WinHeight",String.valueOf(getBounds().height));
		PacketSniffer.preferences.put("WinX",String.valueOf(getBounds().x));
		PacketSniffer.preferences.put("WinY",String.valueOf(getBounds().y));
		
		tablePane.saveProperty();
		
		PacketSniffer.saveProperty();
	}
	
	public void enableCapture(){
		open.setEnabled(true);
		openButton.setEnabled(true);
		save.setEnabled(true);
		saveButton.setEnabled(true);
		start.setEnabled(true);
		captureButton.setEnabled(true);
		stop.setEnabled(false);
		stopButton.setEnabled(false);
	}
	
	public void disableCapture(){
                
		open.setEnabled(false);
                System.out.println("ok");
		openButton.setEnabled(false);
		start.setEnabled(false);
		captureButton.setEnabled(false);
		save.setEnabled(true);
		saveButton.setEnabled(true);
		stop.setEnabled(true);
		stopButton.setEnabled(true);
	}
	
	private ImageIcon getImageIcon(String path){
		return new ImageIcon(this.getClass().getResource(path));
	}
	
	/*ButtonGroup lafGroup=new ButtonGroup();
	private JRadioButtonMenuItem createLaFMenuItem(String name,String lafName){
		JRadioButtonMenuItem item=new JRadioButtonMenuItem(name);
		item.setActionCommand("LaF"+lafName);
		item.addActionListener(this);
		lafGroup.add(item);
		
		try {
			Class lnfClass = Class.forName(lafName);
			LookAndFeel newLAF = (LookAndFeel)(lnfClass.newInstance());
			if(!newLAF.isSupportedLookAndFeel()) item.setEnabled(false);
		} catch(Exception e) {
			item.setEnabled(false);
		}
		
		return item;
	}*/
        
        
}
