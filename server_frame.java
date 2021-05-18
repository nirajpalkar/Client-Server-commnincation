package chat_server;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.xml.bind.DatatypeConverter;

/*import jpcap.*;
import jpcap.NetworkInterface;

import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
*/
public class server_frame extends javax.swing.JFrame 
{
   ArrayList clientOutputStreams,cOutputStreams;
   ArrayList<String> users;
   String encrypt,decrypt;
   File sendf;
//   rec r=new rec();
   
   int l_inc,f_inc,s_inc;

   public class ClientHandler implements Runnable	
   {
       BufferedReader reader;
       Socket sock;
       PrintWriter client;
       
       
       

       public ClientHandler(Socket clientSocket, PrintWriter user) 
       {
            client = user;
            try 
            {
                sock = clientSocket;
                InputStreamReader isReader = new InputStreamReader(sock.getInputStream());
                reader = new BufferedReader(isReader);
                OutputStream os = sock.getOutputStream();
                cOutputStreams.add(os);
                
            }
            catch (Exception ex) 
            {
                ta_operations.append("Unexpected error... \n");
            }

       }

       @Override
       public void run() 
       {
            String message, connect = "Connect", disconnect = "Disconnect", chat = "Chat", receiveCloud="ReceiveCloud",sendCloud="SendCloud",refresh="Refresh" ,cloud="Cloud";
            String[] data;

            try 
            {
                while ((message = reader.readLine()) != null) 
                {
                    decrypt = decryptText(message);
                    createlog(decrypt + "\n");
                    data = decrypt.split(":");
                    //ta_operations.append("Received: " + data[0] + data[1] + "\n");
                    if(!data[2].equals(refresh) && !data[2].equals(sendCloud) && !data[2].equals(cloud))
                    {
                        ta_chat.append(data[0] + ": " + data[1]);
                        ta_chat.append("\n");
                        refreshOl();
                    }
                    if (data[2].equals(connect)) 
                    {
                        tellEveryone((data[0] + ":" + data[1] + ":" + chat));
                        userAdd(data[0],data[3]);
                        refreshOl();
                        
                    } 
                    else if (data[2].equals(disconnect)) 
                    {
                        tellEveryone((data[0] + ": has disconnected." + ":" + chat));
                        userRemove(data[0]);
                        refreshOl();
                    } 
                    else if (data[2].equals(chat)) 
                    {
                        tellEveryone(decrypt);
                    }
                    else if (data[2].equals(refresh)) 
                    {
                        refreshUsers();
                        refreshOl();
                    }
                    
                    else if (data[2].equals(cloud)) 
                    {
                        tellEveryone("Server:"+sendFileList()+ ":Cloud");
                    }
                    else if (data[2].equals(sendCloud)) 
                    {
                        selectFile(data[1]);
                    }
                    else if (data[2].equals(receiveCloud)) 
                    {
                        receiveCloud(data[3],data[1]);
                    }
                    else 
                    {
                        ta_operations.append("No Conditions were met. \n");
                    }
                    
                } 
            } 
            catch (Exception ex) 
            {
                ta_operations.append("Lost a connection. \n");
                clientOutputStreams.remove(client);
            } 
	} 
    }

    public server_frame() 
    {
        initComponents();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        d_disconnect = new javax.swing.JDialog();
        tf_disconnect = new javax.swing.JTextField();
        b_disconnect = new javax.swing.JButton();
        l_name = new javax.swing.JLabel();
        d_addclient = new javax.swing.JDialog();
        tf_username = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        b_addclient = new javax.swing.JButton();
        jLabel8 = new javax.swing.JLabel();
        pf_password = new javax.swing.JPasswordField();
        pf_repassword = new javax.swing.JPasswordField();
        l_match = new javax.swing.JLabel();
        l_checkusername = new javax.swing.JLabel();
        d_done = new javax.swing.JDialog();
        l_done = new javax.swing.JLabel();
        b_ok = new javax.swing.JButton();
        d_removeclient = new javax.swing.JDialog();
        jLabel5 = new javax.swing.JLabel();
        tf_remuser = new javax.swing.JTextField();
        b_remuser = new javax.swing.JButton();
        f_sendf = new javax.swing.JFrame();
        jLabel9 = new javax.swing.JLabel();
        tf_sendf = new javax.swing.JTextField();
        b_sendf = new javax.swing.JButton();
        jScrollPane4 = new javax.swing.JScrollPane();
        ta_sendf = new javax.swing.JTextArea();
        b_browse = new javax.swing.JButton();
        f_recf = new javax.swing.JFrame();
        jScrollPane6 = new javax.swing.JScrollPane();
        ta_recf = new javax.swing.JTextArea();
        jLabel10 = new javax.swing.JLabel();
        cb_extension = new javax.swing.JComboBox();
        tf_setpath = new javax.swing.JTextField();
        b_recf = new javax.swing.JButton();
        b_target = new javax.swing.JButton();
        jLabel11 = new javax.swing.JLabel();
        tf_ip = new javax.swing.JTextField();
        jLabel12 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        ta_chat = new javax.swing.JTextArea();
        b_start = new javax.swing.JButton();
        b_end = new javax.swing.JButton();
        b_clear = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        ta_olusers = new javax.swing.JTextArea();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        ta_operations = new javax.swing.JTextArea();
        tf_chat = new javax.swing.JTextField();
        b_opclear = new javax.swing.JButton();
        b_send = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        jSeparator4 = new javax.swing.JSeparator();
        jSeparator2 = new javax.swing.JSeparator();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenu2 = new javax.swing.JMenu();
        m_resources = new javax.swing.JMenu();
        mi_sendf = new javax.swing.JMenuItem();
        mi_recf = new javax.swing.JMenuItem();
        m_clients = new javax.swing.JMenu();
        mi_addclients = new javax.swing.JMenuItem();
        mi_removeclient = new javax.swing.JMenuItem();
        mi_disconnect = new javax.swing.JMenuItem();
        mi_screenshot = new javax.swing.JMenuItem();
        mi_reclog = new javax.swing.JMenuItem();

        d_disconnect.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        d_disconnect.setBounds(new java.awt.Rectangle(100, 100, 250, 250));

        tf_disconnect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tf_disconnectActionPerformed(evt);
            }
        });

        b_disconnect.setText("Disconnect");
        b_disconnect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_disconnectActionPerformed(evt);
            }
        });

        l_name.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout d_disconnectLayout = new javax.swing.GroupLayout(d_disconnect.getContentPane());
        d_disconnect.getContentPane().setLayout(d_disconnectLayout);
        d_disconnectLayout.setHorizontalGroup(
            d_disconnectLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_disconnectLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_disconnectLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(l_name, javax.swing.GroupLayout.DEFAULT_SIZE, 234, Short.MAX_VALUE)
                    .addComponent(tf_disconnect, javax.swing.GroupLayout.DEFAULT_SIZE, 234, Short.MAX_VALUE)
                    .addComponent(b_disconnect, javax.swing.GroupLayout.DEFAULT_SIZE, 234, Short.MAX_VALUE))
                .addContainerGap())
        );
        d_disconnectLayout.setVerticalGroup(
            d_disconnectLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_disconnectLayout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addComponent(l_name, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(33, 33, 33)
                .addComponent(tf_disconnect, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 43, Short.MAX_VALUE)
                .addComponent(b_disconnect)
                .addGap(59, 59, 59))
        );

        d_addclient.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        d_addclient.setAlwaysOnTop(true);
        d_addclient.setBounds(100, 100, 250, 300);
        d_addclient.setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));

        jLabel4.setText("Username:");

        jLabel6.setText("Password:");

        jLabel7.setText("Insert details of client");

        b_addclient.setText("Add Client");
        b_addclient.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_addclientActionPerformed(evt);
            }
        });

        jLabel8.setText("Re-enter Password:");

        javax.swing.GroupLayout d_addclientLayout = new javax.swing.GroupLayout(d_addclient.getContentPane());
        d_addclient.getContentPane().setLayout(d_addclientLayout);
        d_addclientLayout.setHorizontalGroup(
            d_addclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, d_addclientLayout.createSequentialGroup()
                .addGroup(d_addclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(d_addclientLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(l_match, javax.swing.GroupLayout.DEFAULT_SIZE, 221, Short.MAX_VALUE))
                    .addGroup(d_addclientLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(l_checkusername, javax.swing.GroupLayout.DEFAULT_SIZE, 221, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, d_addclientLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel4)
                        .addGap(62, 62, 62)
                        .addComponent(tf_username, javax.swing.GroupLayout.DEFAULT_SIZE, 107, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, d_addclientLayout.createSequentialGroup()
                        .addGap(64, 64, 64)
                        .addComponent(jLabel7))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, d_addclientLayout.createSequentialGroup()
                        .addGap(78, 78, 78)
                        .addComponent(b_addclient))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, d_addclientLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel8)
                        .addGap(18, 18, 18)
                        .addComponent(pf_repassword, javax.swing.GroupLayout.DEFAULT_SIZE, 107, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, d_addclientLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel6)
                        .addGap(64, 64, 64)
                        .addComponent(pf_password, javax.swing.GroupLayout.DEFAULT_SIZE, 107, Short.MAX_VALUE)))
                .addContainerGap())
        );
        d_addclientLayout.setVerticalGroup(
            d_addclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_addclientLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel7)
                .addGap(9, 9, 9)
                .addGroup(d_addclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tf_username, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(l_checkusername, javax.swing.GroupLayout.DEFAULT_SIZE, 20, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(d_addclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel6)
                    .addComponent(pf_password, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(d_addclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel8)
                    .addComponent(pf_repassword, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(l_match, javax.swing.GroupLayout.PREFERRED_SIZE, 19, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(b_addclient)
                .addContainerGap())
        );

        d_done.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        d_done.setAlwaysOnTop(true);
        d_done.setBounds(100, 100, 250, 250);

        l_done.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);

        b_ok.setText("OK");
        b_ok.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_okActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout d_doneLayout = new javax.swing.GroupLayout(d_done.getContentPane());
        d_done.getContentPane().setLayout(d_doneLayout);
        d_doneLayout.setHorizontalGroup(
            d_doneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_doneLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_doneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(d_doneLayout.createSequentialGroup()
                        .addComponent(l_done, javax.swing.GroupLayout.DEFAULT_SIZE, 252, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, d_doneLayout.createSequentialGroup()
                        .addComponent(b_ok)
                        .addGap(111, 111, 111))))
        );
        d_doneLayout.setVerticalGroup(
            d_doneLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_doneLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(l_done, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 27, Short.MAX_VALUE)
                .addComponent(b_ok)
                .addContainerGap())
        );

        d_removeclient.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        d_removeclient.setAlwaysOnTop(true);
        d_removeclient.setBounds(300,200,300,250);

        jLabel5.setText("Username:");

        b_remuser.setText("Remove");
        b_remuser.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_remuserActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout d_removeclientLayout = new javax.swing.GroupLayout(d_removeclient.getContentPane());
        d_removeclient.getContentPane().setLayout(d_removeclientLayout);
        d_removeclientLayout.setHorizontalGroup(
            d_removeclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_removeclientLayout.createSequentialGroup()
                .addGroup(d_removeclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(d_removeclientLayout.createSequentialGroup()
                        .addGap(55, 55, 55)
                        .addComponent(b_remuser))
                    .addGroup(d_removeclientLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 37, Short.MAX_VALUE)
                        .addComponent(tf_remuser, javax.swing.GroupLayout.PREFERRED_SIZE, 77, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        d_removeclientLayout.setVerticalGroup(
            d_removeclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, d_removeclientLayout.createSequentialGroup()
                .addContainerGap(35, Short.MAX_VALUE)
                .addGroup(d_removeclientLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5)
                    .addComponent(tf_remuser, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(b_remuser)
                .addGap(40, 40, 40))
        );

        f_sendf.setBounds(400,180,400,400);

        jLabel9.setText("File name:");

        b_sendf.setText("Send");
        b_sendf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_sendfActionPerformed(evt);
            }
        });

        ta_sendf.setColumns(20);
        ta_sendf.setEditable(false);
        ta_sendf.setRows(5);
        jScrollPane4.setViewportView(ta_sendf);

        b_browse.setText("Browse");
        b_browse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_browseActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout f_sendfLayout = new javax.swing.GroupLayout(f_sendf.getContentPane());
        f_sendf.getContentPane().setLayout(f_sendfLayout);
        f_sendfLayout.setHorizontalGroup(
            f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, f_sendfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)
                    .addGroup(f_sendfLayout.createSequentialGroup()
                        .addComponent(jLabel9)
                        .addGap(18, 18, 18)
                        .addComponent(tf_sendf, javax.swing.GroupLayout.PREFERRED_SIZE, 82, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(b_browse)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 101, Short.MAX_VALUE)
                        .addComponent(b_sendf)))
                .addContainerGap())
        );
        f_sendfLayout.setVerticalGroup(
            f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(f_sendfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel9)
                    .addComponent(tf_sendf, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_sendf)
                    .addComponent(b_browse))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 249, Short.MAX_VALUE)
                .addContainerGap())
        );

        f_recf.setBounds(400,180,400,400);

        ta_recf.setColumns(20);
        ta_recf.setRows(5);
        jScrollPane6.setViewportView(ta_recf);

        jLabel10.setText("Select Extension :");

        cb_extension.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "pdf", "docx", "java", "jpg", "mp4", "png", "mp3", "zip", "rar", "gif", "accdb", "xml", "exe", "jar", "dll", "html", "c", "cpp", "bak", "php", "pptx", "txt", "xlsx", "psd" }));
        cb_extension.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cb_extensionActionPerformed(evt);
            }
        });

        b_recf.setText("Recieve");
        b_recf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_recfActionPerformed(evt);
            }
        });

        b_target.setText("Browse");
        b_target.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_targetActionPerformed(evt);
            }
        });

        jLabel11.setText("Ip:");

        jLabel12.setText("Traget:");

        javax.swing.GroupLayout f_recfLayout = new javax.swing.GroupLayout(f_recf.getContentPane());
        f_recf.getContentPane().setLayout(f_recfLayout);
        f_recfLayout.setHorizontalGroup(
            f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(f_recfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)
                    .addGroup(f_recfLayout.createSequentialGroup()
                        .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel10)
                            .addComponent(jLabel11)
                            .addComponent(jLabel12))
                        .addGap(18, 18, 18)
                        .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(tf_ip, javax.swing.GroupLayout.PREFERRED_SIZE, 114, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, f_recfLayout.createSequentialGroup()
                                    .addComponent(cb_extension, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(b_recf))
                                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, f_recfLayout.createSequentialGroup()
                                    .addComponent(tf_setpath, javax.swing.GroupLayout.PREFERRED_SIZE, 185, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                    .addComponent(b_target, javax.swing.GroupLayout.PREFERRED_SIZE, 73, javax.swing.GroupLayout.PREFERRED_SIZE))))))
                .addContainerGap())
        );
        f_recfLayout.setVerticalGroup(
            f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(f_recfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel10, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cb_extension, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_recf))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tf_setpath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_target)
                    .addComponent(jLabel12))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel11)
                    .addComponent(tf_ip, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 177, Short.MAX_VALUE)
                .addContainerGap())
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Chat - Server's frame");
        setName("server"); // NOI18N
        setResizable(false);

        ta_chat.setColumns(20);
        ta_chat.setEditable(false);
        ta_chat.setRows(5);
        jScrollPane1.setViewportView(ta_chat);

        b_start.setText("START");
        b_start.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_startActionPerformed(evt);
            }
        });

        b_end.setText("END");
        b_end.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_endActionPerformed(evt);
            }
        });

        b_clear.setText("CLEAR");
        b_clear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_clearActionPerformed(evt);
            }
        });

        ta_olusers.setColumns(20);
        ta_olusers.setEditable(false);
        ta_olusers.setRows(5);
        jScrollPane2.setViewportView(ta_olusers);

        jLabel1.setText("ONLINE");

        jLabel2.setText("OPERATIONS");

        ta_operations.setEditable(false);
        ta_operations.setColumns(20);
        ta_operations.setRows(5);
        jScrollPane3.setViewportView(ta_operations);

        tf_chat.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tf_chatActionPerformed(evt);
            }
        });

        b_opclear.setText("CLEAR");
        b_opclear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_opclearActionPerformed(evt);
            }
        });

        b_send.setText("SEND");
        b_send.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_sendActionPerformed(evt);
            }
        });

        jLabel3.setBackground(new java.awt.Color(102, 100, 98));
        jLabel3.setText("CHATS");

        jSeparator4.setOrientation(javax.swing.SwingConstants.VERTICAL);

        jMenu1.setText("File");
        jMenuBar1.add(jMenu1);

        jMenu2.setText("Edit");
        jMenuBar1.add(jMenu2);

        m_resources.setText("Resources");

        mi_sendf.setText("Send File");
        mi_sendf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_sendfActionPerformed(evt);
            }
        });
        m_resources.add(mi_sendf);

        mi_recf.setText("Receive File");
        mi_recf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_recfActionPerformed(evt);
            }
        });
        m_resources.add(mi_recf);

        jMenuBar1.add(m_resources);

        m_clients.setText("Clients");
        m_clients.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                m_clientsActionPerformed(evt);
            }
        });

        mi_addclients.setText("Add New Client");
        mi_addclients.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_addclientsActionPerformed(evt);
            }
        });
        m_clients.add(mi_addclients);

        mi_removeclient.setText("Remove Client");
        mi_removeclient.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_removeclientActionPerformed(evt);
            }
        });
        m_clients.add(mi_removeclient);

        mi_disconnect.setText("Disconnect Client");
        mi_disconnect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_disconnectActionPerformed(evt);
            }
        });
        m_clients.add(mi_disconnect);

        mi_screenshot.setText("Screenshot");
        mi_screenshot.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_screenshotActionPerformed(evt);
            }
        });
        m_clients.add(mi_screenshot);

        mi_reclog.setText("Get Client logs");
        mi_reclog.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_reclogActionPerformed(evt);
            }
        });
        m_clients.add(mi_reclog);

        jMenuBar1.add(m_clients);

        setJMenuBar(jMenuBar1);
        jMenuBar1.getAccessibleContext().setAccessibleParent(this);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(tf_chat, javax.swing.GroupLayout.PREFERRED_SIZE, 156, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(b_send, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 221, Short.MAX_VALUE))
                        .addGap(20, 20, 20))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 208, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(0, 143, Short.MAX_VALUE)
                        .addComponent(b_clear, javax.swing.GroupLayout.PREFERRED_SIZE, 80, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jSeparator2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 223, Short.MAX_VALUE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(b_start, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 69, Short.MAX_VALUE)
                                .addComponent(b_end, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(18, 18, 18)))
                .addComponent(jSeparator4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 212, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 214, Short.MAX_VALUE)
                        .addGap(8, 8, 8))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 212, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addGap(0, 157, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addContainerGap(185, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(b_opclear)
                        .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addGap(15, 15, 15))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(b_start)
                                .addComponent(b_end)))
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(2, 2, 2)
                                .addComponent(jLabel3)
                                .addGap(18, 18, 18)
                                .addComponent(b_clear)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 274, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                    .addComponent(tf_chat, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(b_send))
                                .addGap(0, 4, Short.MAX_VALUE))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGap(3, 3, 3)
                                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 144, Short.MAX_VALUE)
                                .addGap(37, 37, 37)
                                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel2)
                                .addGap(17, 17, 17)
                                .addComponent(b_opclear)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addComponent(jSeparator4, javax.swing.GroupLayout.DEFAULT_SIZE, 427, Short.MAX_VALUE))
                .addContainerGap())
        );

        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        setBounds((screenSize.width-501)/2, (screenSize.height-508)/2, 501, 508);
    }// </editor-fold>//GEN-END:initComponents

    private void b_endActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_endActionPerformed
        
        tellEveryone("Server:is stopping and all users will be disconnected.:Chat");
        ta_operations.append("Server stopping... \n");
        try 
        {
            Thread.sleep(5000);                 //5000 milliseconds is five second.
        } 
        catch(InterruptedException ex) {Thread.currentThread().interrupt();}
        //r.suspend();
        
    }//GEN-LAST:event_b_endActionPerformed

    private void b_startActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_startActionPerformed
        
        Thread starter = new Thread(new ServerStart());
        starter.start();
        ta_operations.append("Server started...\n");
//        r.start();
    }//GEN-LAST:event_b_startActionPerformed

    private void b_clearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_clearActionPerformed
        
        ta_chat.setText("");
        
    }//GEN-LAST:event_b_clearActionPerformed

    private void tf_chatActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_chatActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_tf_chatActionPerformed

    private void b_opclearActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_opclearActionPerformed
        
        ta_operations.setText("");
        // TODO add your handling code here:
    }//GEN-LAST:event_b_opclearActionPerformed

    private void b_sendActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_sendActionPerformed
        
        String str1=tf_chat.getText();
        ta_chat.append("Server:" + str1 + "\n");
        tf_chat.setText("");
        str1="Server" + ":" + str1 + ":" + "Chat";
        tellEveryone(str1);
// TODO add your handling code here:
    }//GEN-LAST:event_b_sendActionPerformed

    private void mi_sendfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_sendfActionPerformed
        
        f_sendf.setVisible(true);
        
    }//GEN-LAST:event_mi_sendfActionPerformed

    private void mi_disconnectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_disconnectActionPerformed
        tf_disconnect.setText("");
        d_disconnect.setVisible(true);
    }//GEN-LAST:event_mi_disconnectActionPerformed

    private void b_disconnectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_disconnectActionPerformed
        Disconnect(tf_disconnect.getText());
        l_done.setText("User Disconnected");
        d_done.setVisible(true);
    }//GEN-LAST:event_b_disconnectActionPerformed

    private void tf_disconnectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_disconnectActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_tf_disconnectActionPerformed

private void mi_addclientsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_addclientsActionPerformed

    d_addclient.setVisible(true);
}//GEN-LAST:event_mi_addclientsActionPerformed

private void b_addclientActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_addclientActionPerformed
    
    if(checkUsername(tf_username.getText()) && !(tf_username.getText().equals("")))
    {
        l_checkusername.setText("Username Available");
        if(pf_password.getText().equals(pf_repassword.getText()))
        {
            try 
            {
                Class.forName("sun.jdbc.odbc.JdbcOdbcDriver");
                Connection con = DriverManager.getConnection("jdbc:odbc:LoginDB");
                PreparedStatement pstmt=con.prepareStatement("Insert into Login values(?,?)");
                pstmt.setString(1, tf_username.getText());
                pstmt.setString(2, pf_password.getText());
                pstmt.executeUpdate();
                tf_username.setText("");
                pf_password.setText("");
                pf_repassword.setText("");
            } 
 
            catch (SQLException | ClassNotFoundException ex) {}
            
            d_addclient.dispose();
            l_done.setText("Client details added");
            d_done.setVisible(true);
        }
        else
        {
            l_match.setText("Passwords do not match");
            pf_password.setText("");
            pf_repassword.setText("");
        }
    }
    else
    {
        l_checkusername.setText("Username is taken or too short");
    }
}//GEN-LAST:event_b_addclientActionPerformed

private void b_okActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_okActionPerformed

    l_done.setText("");
    d_done.dispose();
}//GEN-LAST:event_b_okActionPerformed

private void mi_removeclientActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_removeclientActionPerformed
     d_removeclient.setVisible(true);
}//GEN-LAST:event_mi_removeclientActionPerformed

private void b_remuserActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_remuserActionPerformed

    try 
            {
                Class.forName("sun.jdbc.odbc.JdbcOdbcDriver");
                Connection con = DriverManager.getConnection("jdbc:odbc:LoginDB");
                PreparedStatement pstmt=con.prepareStatement("Delete from Login where Username=?");
                pstmt.setString(1, tf_remuser.getText());
                
                pstmt.executeUpdate();
                tf_remuser.setText("");
                
            } 
 
            catch (SQLException | ClassNotFoundException ex) {}
            
            d_removeclient.dispose();
            l_done.setText("Client details removed.");
            d_done.setVisible(true);
}//GEN-LAST:event_b_remuserActionPerformed

    private void m_clientsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_m_clientsActionPerformed
        //d_packets.setVisible(true);
      
    }//GEN-LAST:event_m_clientsActionPerformed

    private void b_sendfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_sendfActionPerformed
        try {
            sendf(sendf);
        } catch (IOException ex) {
        }
       
    }//GEN-LAST:event_b_sendfActionPerformed

    private void b_browseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_browseActionPerformed
        
        JFileChooser chooser = new JFileChooser();
        chooser.showOpenDialog(null);
        sendf=chooser.getSelectedFile();
        tf_sendf.setText(sendf.getAbsolutePath());
        
    }//GEN-LAST:event_b_browseActionPerformed

private void b_targetActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_targetActionPerformed
// TODO add your handling code here:
        JFileChooser chooser= new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.showOpenDialog(null);
        tf_setpath.setText(chooser.getSelectedFile().getAbsolutePath());
}//GEN-LAST:event_b_targetActionPerformed

private void b_recfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_recfActionPerformed
        try {
            // TODO add your handling code here:
                receiveFile();
        }
        catch (IOException ex) {
        }
}//GEN-LAST:event_b_recfActionPerformed

private void mi_recfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_recfActionPerformed
        f_recf.setVisible(true);
    
}//GEN-LAST:event_mi_recfActionPerformed

private void mi_screenshotActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_screenshotActionPerformed
    tellEveryone("Server:Send Screenshots:Screenshot");
    try {
       receiveShot();
            } catch (IOException ex) {
            }
    
    l_done.setText("Received");
    d_done.setVisible(true);
    
    
}//GEN-LAST:event_mi_screenshotActionPerformed

private void cb_extensionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cb_extensionActionPerformed
// TODO add your handling code here:
}//GEN-LAST:event_cb_extensionActionPerformed

private void mi_reclogActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_reclogActionPerformed
    tellEveryone("Server:Send Logs:Sniffing");
       receiveLogs();
    
    l_done.setText("Received");
    d_done.setVisible(true);
// TODO add your handling code here:
}//GEN-LAST:event_mi_reclogActionPerformed

    public static void main(String args[]) 
    {
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {java.util.logging.Logger.getLogger(server_frame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);}
        //</editor-fold>
        Path path1,path2,path3,path4;
        File dir1;
        path1 = FileSystems.getDefault().getPath("D:\\Cloud Server");
        path2 = FileSystems.getDefault().getPath("D:\\Cloud Server\\Cloud");
        path3 = FileSystems.getDefault().getPath("D:\\Cloud Server\\Screenshots");
        path4 = FileSystems.getDefault().getPath("D:\\Cloud Server\\Logs");
            if(Files.notExists(path1))
                {
                    dir1=new File("D:\\Cloud Server");
                    Boolean mk=dir1.mkdir();
                }
            if(Files.notExists(path2))
                {
                    dir1=new File("D:\\Cloud Server\\Cloud");
                    Boolean mk=dir1.mkdir();
                }
            if(Files.notExists(path3))
                {
                    dir1=new File("D:\\Cloud Server\\Screenshots");
                    Boolean mk=dir1.mkdir();
                }
            if(Files.notExists(path4))
                {
                    dir1=new File("D:\\Cloud Server\\Logs");
                    Boolean mk=dir1.mkdir();
                }
        java.awt.EventQueue.invokeLater(new Runnable() 
        {
            @Override
            public void run() {
                new server_frame().setVisible(true);
            }
        });
    }
    
    public class ServerStart implements Runnable 
    {
        @Override
        public void run() 
        {
            clientOutputStreams = new ArrayList();
            users = new ArrayList();  
            cOutputStreams = new ArrayList();
            try 
            {
                ServerSocket serverSock = new ServerSocket(2222);

                while (true) 
                {
				Socket clientSock = serverSock.accept();
				PrintWriter writer = new PrintWriter(clientSock.getOutputStream());
				clientOutputStreams.add(writer);
                                
				Thread listener = new Thread(new ClientHandler(clientSock, writer));
				listener.start();
				ta_operations.append("Got a connection. \n");
                }
            }
            catch (Exception ex)
            {
                ta_operations.append("Error making a connection. \n");
            }
        }
    }
    
    //--------------------------//
    
    public void userAdd (String name, String password) 
    {
        
        String message, add = ": :Connect", done = "Server: :Done";
        ta_operations.append("Before " + name + " added. \n");
        users.add(name);
        ta_operations.append("After " + name + " added. \n");
        String[] tempList = new String[(users.size())];
        users.toArray(tempList);
        if(!authenticate(name,password))
        {
            Disconnect(name);
            userRemove(name);
        }
            for (String token:tempList) 
            {
                message = (token + add);
                tellEveryone(message);
            }
            tellEveryone(done);  
    
    }
    
    //--------------------------//
    
    public void userRemove (String data) 
    {
        String message, add = ": :Connect", done = "Server: :Done", name = data;
        users.remove(name);
        String[] tempList = new String[(users.size())];
        users.toArray(tempList);

        for (String token:tempList) 
        {
            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }
    
    //--------------------------//
    
    public void tellEveryone(String message) 
    {
        try {
            Iterator it = clientOutputStreams.iterator();
            encrypt = encryptText(message);
            while (it.hasNext()) 
            {
                try 
                {
                    PrintWriter writer = (PrintWriter) it.next();
                    writer.println(encrypt);
                    //ta_chat.append("Server: " + message + "\n");
                    writer.flush();
                    ta_chat.setCaretPosition(ta_chat.getDocument().getLength());

                } 
                catch (Exception ex) 
                {
                    ta_operations.append("Error telling everyone. \n");
                }
            }
        } 
        catch (Exception ex) {}
    }
    
    //--------------------------//
    
    
    
    public void sendf(File FileToSend) throws IOException
    {
    
    FileInputStream fis = null;
    BufferedInputStream bis = null;
    OutputStream os = null;
    ServerSocket servsock = null;
    Socket sock = null;
    try {
      servsock = new ServerSocket(2223);
      while (true) {
          
          
         
          
          ta_sendf.append("Waiting...");
          sock = servsock.accept();
          ta_sendf.append("Accepted connection : " + sock);
          // send file
          File myFile = FileToSend;
          tf_sendf.setText(myFile.getAbsolutePath());
          byte [] mybytearray  = new byte [(int)myFile.length()];
          fis = new FileInputStream(myFile);
          bis = new BufferedInputStream(fis);
          bis.read(mybytearray,0,mybytearray.length);
          os = sock.getOutputStream();
          ta_sendf.append("Sending " + myFile.getAbsolutePath() + "(" + mybytearray.length + " bytes)");
          os.write(mybytearray,0,mybytearray.length);
          os.flush();
          ta_sendf.append("Done.");
          bis.close();
          os.close();
          sock.close();
          servsock.close();
      } 
         
        
      
      
    }
        catch (IOException ex) {
    }
    
    }
    
    public void selectFile(String name) throws IOException
    {
        sendf = new File("D:\\Cloud Server\\Cloud\\" + name);
        sendf(sendf);
    }
    
    
    //--------------------------//
    
    public void refreshOl()
    {
        Iterator it = users.iterator();
        String msg="",finalmsg;
        while(it.hasNext())
        {
            msg = msg + (String)it.next() + "\n";
        }
        ta_olusers.setText(msg);
    
    }
    
    public void refreshUsers()
    {
        Iterator it = users.iterator();
        String msg="",finalmsg;
        while(it.hasNext())
        {
            msg = msg + (String)it.next() + "\n";
        }
        finalmsg = "Server:" + msg + ":Refresh";
        tellEveryone(finalmsg);
    }
    
    public String sendFileList()
    {
        String list="";
        File folder = new File("D:\\Cloud Server\\Cloud");
        File[] listOfFiles = folder.listFiles();

        for (int i2 = 0; i2 < listOfFiles.length; i2++) {
        list = list + listOfFiles[i2].getName()+ "\n" ;
        }
        return list;
    }
    //--------------------------//
    
    public boolean authenticate(String username, String password)
    {
        int flag=0;
        try {
            Class.forName("sun.jdbc.odbc.JdbcOdbcDriver");
            Connection con = DriverManager.getConnection("jdbc:odbc:LoginDB");
            Statement stmt=con.createStatement();
            ResultSet rs=stmt.executeQuery("select * from Login");
            while(rs.next())
            {
                String str1 = rs.getString(1);
                String str2 = rs.getString(2);
                if(str1.equals(username) && str2.equals(password))
                {
                    flag++;
                }
            }
        } 
 
        catch (ClassNotFoundException | SQLException ex) { Logger.getLogger(server_frame.class.getName()).log(Level.SEVERE, null, ex);} 
        if(flag!=0)
            return(true);
        else
            return(false);
    }
    
    public boolean checkUsername(String str)
    {
        int flag=0;
        try {
            Class.forName("sun.jdbc.odbc.JdbcOdbcDriver");
                Connection con = DriverManager.getConnection("jdbc:odbc:LoginDB");
                Statement stmt=con.createStatement();
                ResultSet rs=stmt.executeQuery("select * from Login");
           
                while(rs.next())
                {
                    String str1 = rs.getString(1);
                    if(str1.equals(str))
                    {
                        flag++;
                    }
                }
                
        } catch (SQLException | ClassNotFoundException ex) {}
        if(flag==0)
                return(true);
            else
                return(false);
    }
    
    public void receiveLogs()
    {

        String[] iplist ={"192.168.0.103"};
            int k=iplist.length;
        int j=0; 
        while(j<k)
        {
            String ip = iplist[j];
            j++;
         
        
        
        
        String FILE_TO_RECEIVED = "D:\\Cloud Server\\Logs\\Log_"+l_inc+".log";
        int FILE_SIZE=6022386;
        l_inc++;
        
        int bytesRead;
    int current = 0;
    FileOutputStream fos = null;
    BufferedOutputStream bos = null;
    Socket sock = null;
    try {
        
      sock = new Socket(ip,2223);
      ta_recf.append("Connecting...");

      // receive file
      byte [] mybytearray  = new byte [FILE_SIZE];
      InputStream is = sock.getInputStream();
      fos = new FileOutputStream(FILE_TO_RECEIVED);
      bos = new BufferedOutputStream(fos);
      bytesRead = is.read(mybytearray,0,mybytearray.length);
      current = bytesRead;

      do {
         bytesRead =
            is.read(mybytearray, current, (mybytearray.length-current));
         if(bytesRead >= 0) current += bytesRead;
      } while(bytesRead > -1);

      bos.write(mybytearray, 0 , current);
      bos.flush();
      ta_recf.append("File " + FILE_TO_RECEIVED
          + " downloaded (" + current + " bytes read)");
    }
        catch ( IOException ex) {
        }    finally {
            try {
                if (fos != null) fos.close();
                if (bos != null) bos.close();
                if (sock != null) sock.close();
            } catch (IOException ex) {
            }
    }
         
        }
    }
    
    //--------------------------//
    
    public void Disconnect(String user)
    {
        Iterator it = clientOutputStreams.iterator();
        Iterator it1 = users.iterator();
        String client = user;
        String message = "Server :You have been disconnected by Server :Serverkill";
        String str;
        
        while (it.hasNext()) 
        {
            
            if((it1.next()).equals(client))
            {
                try
                {
                    PrintWriter writer = (PrintWriter) it.next();
                    encrypt = encryptText(message);
                    writer.println(encrypt);
                    ta_operations.append(message);
                    writer.flush();
                    ta_chat.setCaretPosition(ta_chat.getDocument().getLength());
                    str = (String)it1.next();
                    userRemove(str);
                }
                catch (Exception ex){ta_operations.append("Error disconnecting" + client + "\n");}
            }
        }
    }
    
    //--------------------------//
    
    public static String encryptText(String plainText) throws Exception
    {
        
        byte[] encoded={'1','2','3','4','1','2','3','4','1','2','3','4','1','2','3','4'};
        SecretKey secKey = new SecretKeySpec(encoded,"AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, secKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return DatatypeConverter.printHexBinary(byteCipherText);
    }
    
    //--------------------------//
    
    public static String decryptText(String cipherText) throws Exception 
    {
        
	byte[] encoded={'1','2','3','4','1','2','3','4','1','2','3','4','1','2','3','4'};
        SecretKey secKey = new SecretKeySpec(encoded,"AES");
        int len = cipherText.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) 
        {
            data[i / 2] = (byte) ((Character.digit(cipherText.charAt(i), 16) << 4)+ Character.digit(cipherText.charAt(i+1), 16));
        }
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(data);
        return new String(bytePlainText);
    }
    
    public void createlog(String msg)
    {
        File dir;
            Path path;
            String dirpath="D:\\Cloud Server\\Logs\\";
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
        fh = new FileHandler("D:\\Cloud Server\\Server log\\Clients.log",true);  
        logger.addHandler(fh);
        SimpleFormatter formatter = new SimpleFormatter();  
        fh.setFormatter(formatter);  

        // the following statement is used to log any messages  
        logger.info(msg);

    } catch (SecurityException | IOException e) {  
    }  

    }
    
    public void receiveFile() throws IOException
    {
        
        f_recf.setVisible(true);
        String ip = tf_ip.getText();
        if(!"".equals(tf_setpath.getText()))
        {
            String str=(String)cb_extension.getSelectedItem();
        String FILE_TO_RECEIVED = tf_setpath.getText() + "\\File" + f_inc +"." +str;
        
        f_inc++;
        
        int bytesRead;
    int current = 0;
    FileOutputStream fos = null;
    BufferedOutputStream bos = null;
    Socket sock = null;
    try {
        
      sock = new Socket(ip,2223);
      ta_recf.append("Connecting...");

      // receive file
      byte [] mybytearray  = new byte [999999999];
      InputStream is = sock.getInputStream();
      fos = new FileOutputStream(FILE_TO_RECEIVED);
      bos = new BufferedOutputStream(fos);
      bytesRead = is.read(mybytearray,0,mybytearray.length);
      current = bytesRead;

      do {
         bytesRead =
            is.read(mybytearray, current, (mybytearray.length-current));
         if(bytesRead >= 0) current += bytesRead;
      } while(bytesRead > -1);

      bos.write(mybytearray, 0 , current);
      bos.flush();
      ta_recf.append("File " + FILE_TO_RECEIVED
          + " downloaded (" + current + " bytes read)");
    }
        catch ( IOException ex) {
        }    finally {
            try {
                if (fos != null) fos.close();
                if (bos != null) bos.close();
                if (sock != null) sock.close();
            } catch (IOException ex) {
            }
    }
    }
        else
            tf_setpath.setText("Select path");
}
    public void receiveShot() throws IOException
    {
        String[] iplist = {"192.168.0.103"};
        //int a=0;
        int k=iplist.length;
        int j=0; 
        while(j<k)
        {
            String ip = iplist[j];
            j++;
         
               
        
        String FILE_TO_RECEIVED = "D:\\Cloud Server\\Screenshots\\ScreenShot_"+s_inc+".png";
        int FILE_SIZE=6022386;
        s_inc++;
        
        int bytesRead;
    int current = 0;
    FileOutputStream fos = null;
    BufferedOutputStream bos = null;
    Socket sock = null;
    try {
        
      sock = new Socket(ip,2223);
      ta_recf.append("Connecting...");

      // receive file
      byte [] mybytearray  = new byte [FILE_SIZE];
      InputStream is = sock.getInputStream();
      fos = new FileOutputStream(FILE_TO_RECEIVED);
      bos = new BufferedOutputStream(fos);
      bytesRead = is.read(mybytearray,0,mybytearray.length);
      current = bytesRead;

      do {
         bytesRead =
            is.read(mybytearray, current, (mybytearray.length-current));
         if(bytesRead >= 0) current += bytesRead;
      } while(bytesRead > -1);

      bos.write(mybytearray, 0 , current);
      bos.flush();
      ta_recf.append("File " + FILE_TO_RECEIVED
          + " downloaded (" + current + " bytes read)");
    }
        catch (IOException ex) {
        }    finally {
            try {
                if (fos != null) fos.close();
                if (bos != null) bos.close();
                if (sock != null) sock.close();
            } catch (IOException ex) {
            }
    }
         
        }
    }
    public void receiveCloud(String currentip,String filename)
    {

        
            String ip = currentip;
           
         
        
        
        
        String FILE_TO_RECEIVED = "D:\\Cloud Server\\Cloud\\"+filename;
        int FILE_SIZE=6022386;
        
        
        int bytesRead;
    int current = 0;
    FileOutputStream fos = null;
    BufferedOutputStream bos = null;
    Socket sock = null;
    try {
        
      sock = new Socket(ip,2223);
      //ta_recf.append("Connecting...");

      // receive file
      byte [] mybytearray  = new byte [FILE_SIZE];
      InputStream is = sock.getInputStream();
      fos = new FileOutputStream(FILE_TO_RECEIVED);
      bos = new BufferedOutputStream(fos);
      bytesRead = is.read(mybytearray,0,mybytearray.length);
      current = bytesRead;

      do {
         bytesRead =
            is.read(mybytearray, current, (mybytearray.length-current));
         if(bytesRead >= 0) current += bytesRead;
      } while(bytesRead > -1);

      bos.write(mybytearray, 0 , current);
      bos.flush();
      //ta_recf.append("File " + FILE_TO_RECEIVED
          //+ " downloaded (" + current + " bytes read)");
    }
        catch ( IOException ex) {
        }    finally {
            try {
                if (fos != null) fos.close();
                if (bos != null) bos.close();
                if (sock != null) sock.close();
            } catch (IOException ex) {
            }
    }
         
        
    }
    
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton b_addclient;
    private javax.swing.JButton b_browse;
    private javax.swing.JButton b_clear;
    private javax.swing.JButton b_disconnect;
    private javax.swing.JButton b_end;
    private javax.swing.JButton b_ok;
    private javax.swing.JButton b_opclear;
    private javax.swing.JButton b_recf;
    private javax.swing.JButton b_remuser;
    private javax.swing.JButton b_send;
    private javax.swing.JButton b_sendf;
    private javax.swing.JButton b_start;
    private javax.swing.JButton b_target;
    private javax.swing.JComboBox cb_extension;
    private javax.swing.JDialog d_addclient;
    private javax.swing.JDialog d_disconnect;
    private javax.swing.JDialog d_done;
    private javax.swing.JDialog d_removeclient;
    private javax.swing.JFrame f_recf;
    private javax.swing.JFrame f_sendf;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JSeparator jSeparator4;
    private javax.swing.JLabel l_checkusername;
    private javax.swing.JLabel l_done;
    private javax.swing.JLabel l_match;
    private javax.swing.JLabel l_name;
    private javax.swing.JMenu m_clients;
    private javax.swing.JMenu m_resources;
    private javax.swing.JMenuItem mi_addclients;
    private javax.swing.JMenuItem mi_disconnect;
    private javax.swing.JMenuItem mi_recf;
    private javax.swing.JMenuItem mi_reclog;
    private javax.swing.JMenuItem mi_removeclient;
    private javax.swing.JMenuItem mi_screenshot;
    private javax.swing.JMenuItem mi_sendf;
    private javax.swing.JPasswordField pf_password;
    private javax.swing.JPasswordField pf_repassword;
    private javax.swing.JTextArea ta_chat;
    private javax.swing.JTextArea ta_olusers;
    private javax.swing.JTextArea ta_operations;
    private javax.swing.JTextArea ta_recf;
    private javax.swing.JTextArea ta_sendf;
    private javax.swing.JTextField tf_chat;
    private javax.swing.JTextField tf_disconnect;
    private javax.swing.JTextField tf_ip;
    private javax.swing.JTextField tf_remuser;
    private javax.swing.JTextField tf_sendf;
    private javax.swing.JTextField tf_setpath;
    private javax.swing.JTextField tf_username;
    // End of variables declaration//GEN-END:variables
}
