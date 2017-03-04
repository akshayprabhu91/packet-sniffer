package packetsniffer.ui;
import jpcap.packet.*;
import java.awt.*;
import javax.swing.*;
import javax.swing.tree.*;
import java.util.*;
import java.util.List;

import packetsniffer.PSPacketAnalyzerLoader;
import packetsniffer.analyzer.PSPacketAnalyzer;

class JDTableTree extends JComponent
{
	JTree tree;
	DefaultMutableTreeNode root=new DefaultMutableTreeNode();
	List<PSPacketAnalyzer> analyzers=PSPacketAnalyzerLoader.getAnalyzers();
	
	JDTableTree(){
		tree=new JTree(root);
		tree.setRootVisible(false);
		JScrollPane treeView=new JScrollPane(tree);
		
		setLayout(new BorderLayout());
		add(treeView,BorderLayout.CENTER);
	}
	
	void analyzePacket(Packet packet){
		boolean[] isExpanded=new boolean[root.getChildCount()];
		for(int i=0;i<root.getChildCount();i++)
			isExpanded[i]=tree.isExpanded(new TreePath(((DefaultMutableTreeNode)root.getChildAt(i)).getPath()));
		
		root.removeAllChildren();
		
		DefaultMutableTreeNode node;
		for(PSPacketAnalyzer analyzer:analyzers){
			if(analyzer.isAnalyzable(packet)){
				analyzer.analyze(packet);
				node=new DefaultMutableTreeNode(analyzer.getProtocolName());
				root.add(node);
				String[] names=analyzer.getValueNames();
				Object[] values=analyzer.getValues();
				if(names==null) continue;
				
				for(int j=0;j<names.length;j++){
					if(values[j] instanceof Vector){
						addNodes(node,names[j],(Vector)values[j]);
					}else if(values[j]!=null){
						addNode(node,names[j]+": "+values[j]);
					}/*else{
						addNode(node,names[j]+": Not available");
					}*/
				}
			}
		}
		((DefaultTreeModel)tree.getModel()).nodeStructureChanged(root);
		
		for(int i=0;i<Math.min(root.getChildCount(),isExpanded.length);i++)
			if(isExpanded[i]) tree.expandPath(new TreePath(((DefaultMutableTreeNode)root.getChildAt(i)).getPath()));
	}

	private void addNode(DefaultMutableTreeNode node,String str){
		node.add(new DefaultMutableTreeNode(str));
	}
	
	private void addNodes(DefaultMutableTreeNode node,String str,Vector v){
		DefaultMutableTreeNode subnode=new DefaultMutableTreeNode(str);
		
		for(int i=0;i<v.size();i++)
			subnode.add(new DefaultMutableTreeNode(v.elementAt(i)));
		
		node.add(subnode);
	}
	
	private void setUserObject(TreeNode node,Object obj){
		((DefaultMutableTreeNode)node).setUserObject(obj);
	}
}
