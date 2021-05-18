package logger1;
import jpcap.*;
import jpcap.NetworkInterface;

import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.*;

class arp_spoofing implements PacketReceiver {
   
    static int i = 0;
    String protocoll[] = {"HOPOPT", "ICMP", "IGMP", "GGP", "IPV4", "ST", "TCP", "CBT", "EGP", "IGP", "BBN", "NV2", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "mux"};

    @Override
    public void receivePacket(Packet packet) {
        //System.out.println(packet + "\n");
        createlog("log creation starts");
        createlog(packet + "\n");
        createlog("this is packet " + i + " :" + "\n");
        i++;

      IPPacket tpt=(IPPacket)packet;
 if (packet != null) {

int ppp=tpt.protocol;
String proto=protocoll[ppp];
createlog("about the ip packet in network layer : \n");
createlog("******************************************************************");
if(tpt.dont_frag){
   createlog("dft bi is set. packet will not be fragmented \n");

}else{
    createlog("dft bi is not set. packet will  be fragmented \n");
}
createlog(" \n destination ip is :"+tpt.dst_ip);
createlog("\n this is source ip :"+tpt.src_ip);
createlog("\n this is hop limit :"+tpt.hop_limit);
createlog(" \n this is identification field  :"+tpt.ident);
createlog(" \npacket length :"+tpt.length);
createlog("\n packet priority  :"+(int)tpt.priority);
createlog("type of service field"+tpt.rsv_tos);
if(tpt.r_flag){
    createlog("releiable transmission");
}else{
    createlog("not reliable");
}
createlog("protocol version is : "+(int)tpt.version);
createlog("flow label field"+tpt.flow_label);

createlog("**********************************************************************");

createlog("datalink lavel analysis");
createlog("********************************************************************");
 DatalinkPacket dp = packet.datalink;


            EthernetPacket ept=(EthernetPacket)dp;
            createlog("this is destination mac address :"+ept.getDestinationAddress());
            createlog("\n this is source mac address"+ept.getSourceAddress());
           


createlog("*********************************************************************");
createlog("this is about type of packet");
createlog("******************************************************************************");
             
            switch (proto) {
                case "TCP":
                    createlog(" /n this is TCP packet");
                    TCPPacket tp = (TCPPacket) packet;
                    createlog("this is destination port of tcp :" + tp.dst_port);
                    if (tp.ack) {
                        createlog("\n" + "this is an acknowledgement");
                    } else {
                        createlog("this is not an acknowledgment packet");
                    }
                    if (tp.rst) {
                        createlog("reset connection ");
                    }
                    createlog(" \n protocol version is :" + tp.version);
                    createlog("\n this is destination ip " + tp.dst_ip);
                    createlog("this is source ip"+tp.src_ip);
                    if(tp.fin){
                        createlog("sender does not have more data to transfer");
                    }if(tp.syn){
                        createlog("\n request for connection");
                    }
                    break;
                case "ICMP":
                    ICMPPacket ipc=(ICMPPacket)packet;
                    // java.net.InetAddress[] routers=ipc.router_ip;
                    //for(int t=0;t
                    //  System.out.println("\n"+routers[t]);
                    // }
                    createlog(" \n this is alive time :"+ipc.alive_time);
                    createlog("\n number of advertised address :"+(int)ipc.addr_num);
                    createlog("mtu of the packet is :"+(int)ipc.mtu);
                    createlog("subnet mask :"+ipc.subnetmask);
                    createlog("\n source ip :"+ipc.src_ip);
                    createlog("\n destination ip:"+ipc.dst_ip);
                    createlog("\n check sum :"+ipc.checksum);
                    createlog("\n icmp type :"+ipc.type);
                    createlog("");
                    break;
                case "UDP":
                    UDPPacket pac=(UDPPacket)packet;
                    createlog("this is udp packet \n");
                    createlog("this is source port :"+pac.src_port);
                    createlog("this is destination port :"+pac.dst_port);
                    break;
                default:
                    break;
            }

              createlog("******************************************************");

            }




        }

   

    public static void main(String str[]) throws Exception {
       
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
           System.out.println("spoofing is started");


        for (int i = 0; i<devices.length; i++) {
            System.out.println(i + " :" + devices[i].name + "(" + devices[i].description + ")");
            System.out.println("    data link:" + devices[i].datalink_name + "("
                    + devices[i].datalink_description + ")");
            System.out.print("    MAC address:");
            for (byte b : devices[i].mac_address) {
                System.out.print(Integer.toHexString(b &0xff) + ":");
            }
            System.out.println();
            for (NetworkInterfaceAddress a : devices[i].addresses) {
                System.out.println("    address:" + a.address + " " + a.subnet + " "
                        + a.broadcast);
            }
        }

        JpcapCaptor jpcap = JpcapCaptor.openDevice(devices[0], 2000, true, 20);

        jpcap.loopPacket(-1, new arp_spoofing());
    }

 public void createlog(String msg)
    {
        File dir;
            Path path;
            String dirpath="D:\\Cloud Server\\spoofing log\\";
            path=FileSystems.getDefault().getPath(dirpath);
            
            if(Files.notExists(path))
            {
                dir = new File(dirpath);
                dir.mkdir();
                
            }
            
            
            
         Logger logger = Logger.getLogger("MyLog");  
    FileHandler fh;  

    try {  

        // This block configure the logger with handler and formatter  
        fh = new FileHandler("D:\\Cloud Clients\\Logs\\Clients1.log",true);  
        logger.addHandler(fh);
        SimpleFormatter formatter = new SimpleFormatter();  
        fh.setFormatter(formatter);  

        // the following statement is used to log any messages  
        logger.info(msg);

    } catch (SecurityException | IOException e) {  
    }  

   
    }}