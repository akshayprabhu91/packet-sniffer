package packetsniffer.analyzer;
import jpcap.packet.*;

public abstract class PSPacketAnalyzer
{
	public int layer=DATALINK_LAYER;
	public static int DATALINK_LAYER=0;
	public static int NETWORK_LAYER=1;
	public static int TRANSPORT_LAYER=2;
	public static int APPLICATION_LAYER=3;
	
	public abstract boolean isAnalyzable(Packet packet);
	public abstract void analyze(Packet packet);
	public abstract String getProtocolName();
	public abstract String[] getValueNames();
	public abstract Object getValue(String valueName);
	abstract Object getValueAt(int index);
	public abstract Object[] getValues();
}
