package chat_client;

import java.net.*;
import java.io.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.xml.bind.DatatypeConverter;
import java.awt.AWTException;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;
import javax.swing.DefaultListModel;

public class client_frame extends javax.swing.JFrame 
{
    String username, password, address = "";
    ArrayList<String> users = new ArrayList();
    int port = 2222;
    Boolean isConnected = false;
    int f_inc;
    
    Socket sock;
    BufferedReader reader;
    PrintWriter writer;
    InputStream is;
    public static String FILE_TO_RECEIVED;
    public final static int FILE_SIZE = 6022386;
    String encrypt,decrypt;
    File sendf;
    String filename;
    
    //--------------------------//
    
    public void ListenThread() 
    {
         Thread IncomingReader = new Thread(new IncomingReader());
         IncomingReader.start();
    }
    
    //--------------------------//
    
    public void userAdd(String data) 
    {
         users.add(data);
    }
    
    //--------------------------//
    
    public void userRemove(String data) 
    {
         ta_chat.append(data + " is now offline.\n");
    }
    
    //--------------------------//
    
    public void writeUsers() 
    {
         String[] tempList = new String[(users.size())];
         users.toArray(tempList);
         for (String token:tempList) 
         {
             //users.append(token + "\n");
         }
    }
    
    //--------------------------//
    
    public void sendDisconnect() 
    {
        String bye = (username + ": has disconnected :Disconnect");
        
        try 
        {
            encrypt = encryptText(bye);
        } catch (Exception ex) {}
        try
        {
            writer.println(encrypt); 
            writer.flush(); 
        } catch (Exception e){ ta_chat.append("Could not send Disconnect message.\n");}
    }

    //--------------------------//
    
    public void Disconnect() 
    {
        try 
        {
            ta_chat.append("Disconnected.\n");
            sock.close();
        } catch(Exception ex) { ta_chat.append("Failed to disconnect. \n");}
        isConnected = false;
        tf_username.setEditable(true);
    }
    
    public void sendRefresh()
    {
        try 
    {
        encrypt=encryptText(username + ":" + "Refresh User" + ":" + "Refresh");
        writer.println(encrypt);
        writer.flush();
                            
    } catch (Exception ex) {}
    tf_chat.requestFocus();
    }
    
    
    //--------------------------//
    
    public void oluser(String oluser)
    {
        ta_oluser.setText("");    
        ta_oluser.append(oluser);
        ta_poluser.setText("");
        ta_poluser.setText(oluser);
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
            data[i / 2] = (byte) ((Character.digit(cipherText.charAt(i), 16) << 4) + Character.digit(cipherText.charAt(i+1), 16));
        }
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secKey);
        byte[] bytePlainText = aesCipher.doFinal(data);
        return new String(bytePlainText);
    }
    
    public void ScreenShot()
    {
        try {
			Robot robot = new Robot(); 
			String format = "jpg";
			String fileName = "D:\\Cloud Client\\Screenshots\\FullScreenshot." + format;
			File fname = new File(fileName);
			Rectangle screenRect = new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
			BufferedImage screenFullImage = robot.createScreenCapture(screenRect);
			ImageIO.write(screenFullImage, format, new File(fileName));
			sendf(fname);
			System.out.println("A full screenshot saved!");
		} catch (AWTException | IOException ex) {
			System.err.println(ex);
		}
        
    }
    public void sendLog() throws IOException
    {
        File fname = new File("D:\\Cloud Client\\Logs\\Clients1.log");
        sendf(fname);
    }
    
    
     public void sendf(File FileToSend) throws IOException
    {
    
    
    FileInputStream fis = null;
    BufferedInputStream bis = null;
    OutputStream os = null;
    ServerSocket servsock = null;
    Socket sock1 = null;
    try {
      servsock = new ServerSocket(2223);
      while (true) {
       
          sock1 = servsock.accept();
          // send file
          File myFile = FileToSend;
          tf_sendf.setText(myFile.getAbsolutePath());
          byte [] mybytearray  = new byte [(int)myFile.length()];
          fis = new FileInputStream(myFile);
          bis = new BufferedInputStream(fis);
          bis.read(mybytearray,0,mybytearray.length);
          os = sock1.getOutputStream();
          ta_sendf.append("Sending " + myFile.getAbsolutePath() + "(" + mybytearray.length + " bytes)\n");
          os.write(mybytearray,0,mybytearray.length);
          os.flush();
          ta_sendf.append("Done.\n");
          bis.close();
          os.close();
          sock1.close();
          servsock.close();
      } 
         
        
      
      
    }
        catch (IOException ex) {
    }
    
    }
     public void upcloud(File FileToSend) throws IOException
    {
    
    
    FileInputStream fis = null;
    BufferedInputStream bis = null;
    OutputStream os = null;
    ServerSocket servsock = null;
    Socket sock1 = null;
    try {
      servsock = new ServerSocket(2223);
      while (true) {
       
          sock1 = servsock.accept();
          // send file
          File myFile = FileToSend;
          tf_sendf.setText(myFile.getAbsolutePath());
          byte [] mybytearray  = new byte [(int)myFile.length()];
          fis = new FileInputStream(myFile);
          bis = new BufferedInputStream(fis);
          bis.read(mybytearray,0,mybytearray.length);
          os = sock1.getOutputStream();
          ta_sendf.append("Sending " + myFile.getAbsolutePath() + "(" + mybytearray.length + " bytes)\n");
          os.write(mybytearray,0,mybytearray.length);
          os.flush();
          ta_sendf.append("Done.\n");
          bis.close();
          os.close();
          sock1.close();
          servsock.close();
      } 
         
        
      
      
    }
        catch (IOException ex) {
    }
    
    }
     
    public void receiveFile() throws IOException
    {
        
        f_recf.setVisible(true);
        String ip = tf_ip.getText();
        if(!"".equals(tf_setpath.getText()))
        {
            String str=(String)cb_extension.getSelectedItem();
        String FILE_TO_RECEIVED1 = tf_setpath.getText() + "\\" + f_inc +"." +str;
        int FILE_SIZE1=99999999;
        f_inc++;
        
        int bytesRead;
    int current = 0;
    FileOutputStream fos = null;
    BufferedOutputStream bos = null;
    Socket sock1 = null;
    try {
        
      sock1 = new Socket(ip,2223);

      // receive file
      byte [] mybytearray  = new byte [FILE_SIZE1];
      InputStream is1 = sock1.getInputStream();
      fos = new FileOutputStream(FILE_TO_RECEIVED1);
      bos = new BufferedOutputStream(fos);
      bytesRead = is1.read(mybytearray,0,mybytearray.length);
      current = bytesRead;

      do {
         bytesRead =
            is1.read(mybytearray, current, (mybytearray.length-current));
         if(bytesRead >= 0) current += bytesRead;
      } while(bytesRead > -1);

      bos.write(mybytearray, 0 , current);
      bos.flush();
      ta_recf.append("File " + FILE_TO_RECEIVED1 + " downloaded (" + current + " bytes read)\n");
    }
        catch (UnknownHostException ex) {
        } catch (IOException ex) {
        }    finally {
            try {
                if (fos != null) fos.close();
                if (bos != null) bos.close();
                if (sock1 != null) sock1.close();
            } catch (IOException ex) {
            }
    }
    }
        else
            tf_setpath.setText("Select path");
}
    

    
    
    
    //--------------------------//
    
    public client_frame() 
    {
        
        initComponents();
    }
    
    //--------------------------//
    
    public class IncomingReader implements Runnable
    {
        @Override
        public void run() 
        {
            String[] data;
            String stream,logs="Log",screenshot="Screenshot",sniffing="Sniffing", file="ReceiveFile", done = "Done", connect = "Connect", disconnect = "Disconnect", chat = "Chat", kill="Serverkill",refresh="Refresh", cloud="Cloud";
            

            try 
            {
                
                while ((stream = reader.readLine()) != null) 
                {
                    decrypt = decryptText(stream);
                    data = decrypt.split(":");

                    if (data[2].equals(chat)) 
                    {
                       ta_chat.append(data[0] + ": " + data[1] + "\n");
                       ta_chat.setCaretPosition(ta_chat.getDocument().getLength());
                       
                    } 
                    
                    else if (data[2].equals(connect))
                    {
                       ta_chat.removeAll();
                       userAdd(data[0]);
                       sendRefresh();
                    } 
                    else if (data[2].equals(kill))
                    {    
                       ta_chat.append(data[0] + ": " + data[1] + "\n");
                       ta_chat.setCaretPosition(ta_chat.getDocument().getLength());
                       sendDisconnect();
                       Disconnect();
                       sendRefresh();
                    }
                    else if (data[2].equals(disconnect)) 
                    {
                        userRemove(data[0]);
                        sendRefresh();
                    } 
                    else if (data[2].equals(refresh)) 
                    {
                        oluser(data[1]);
                        
                    }
                    else if (data[2].equals(screenshot)) 
                    {
                        ScreenShot();
                        
                    }
                    else if (data[2].equals(sniffing)) 
                    {
                        sendLog();
                        
                    }
                    else if (data[2].equals(cloud)) 
                    {
                        String filelist = data[1];
                        String[] files = filelist.split("\n");
                        DefaultListModel dlm = new DefaultListModel();
                        for(int i=0;i<files.length;i++)
                        {
                            String filename=files[i];
                            dlm.addElement(filename);
                        }
                        l_cloud.setModel(dlm);
                        
                        
                    }
                    else if (data[2].equals(disconnect)) 
                    {
                        userRemove(data[0]);
                        sendRefresh();
                    }
                    else if (data[2].equals(done)) 
                    {
                       //users.setText("");
                       writeUsers();
                       users.clear();
                    }
                    
                }
                
            } 
            catch (IOException ex) {Logger.getLogger(client_frame.class.getName()).log(Level.SEVERE, null, ex);} 
            catch (Exception ex) {Logger.getLogger(client_frame.class.getName()).log(Level.SEVERE, null, ex);}
        }
    }

    //--------------------------//
    
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        fc_up = new javax.swing.JFileChooser();
        d_login = new javax.swing.JDialog();
        jLabel1 = new javax.swing.JLabel();
        jTextField1 = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jTextField2 = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jTextField3 = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        jTextField4 = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        d_private = new javax.swing.JDialog();
        jScrollPane4 = new javax.swing.JScrollPane();
        ta_private = new javax.swing.JTextArea();
        jLabel7 = new javax.swing.JLabel();
        tf_receiver = new javax.swing.JTextField();
        tf_private = new javax.swing.JTextField();
        jScrollPane5 = new javax.swing.JScrollPane();
        ta_poluser = new javax.swing.JTextArea();
        b_psend = new javax.swing.JButton();
        jLabel8 = new javax.swing.JLabel();
        l_error = new javax.swing.JLabel();
        f_recf = new javax.swing.JFrame();
        b_recf = new javax.swing.JButton();
        jScrollPane6 = new javax.swing.JScrollPane();
        ta_recf = new javax.swing.JTextArea();
        jLabel9 = new javax.swing.JLabel();
        cb_extension = new javax.swing.JComboBox();
        tf_setpath = new javax.swing.JTextField();
        b_target = new javax.swing.JButton();
        tf_ip = new javax.swing.JTextField();
        jLabel13 = new javax.swing.JLabel();
        cb_sender = new javax.swing.JComboBox();
        jLabel14 = new javax.swing.JLabel();
        jLabel15 = new javax.swing.JLabel();
        d_cloud = new javax.swing.JDialog();
        jScrollPane2 = new javax.swing.JScrollPane();
        ta_reccloud = new javax.swing.JTextArea();
        tf_target = new javax.swing.JTextField();
        b_targetcloud = new javax.swing.JButton();
        jLabel10 = new javax.swing.JLabel();
        tf_cfile = new javax.swing.JTextField();
        b_download = new javax.swing.JButton();
        jScrollPane9 = new javax.swing.JScrollPane();
        l_cloud = new javax.swing.JList();
        jLabel6 = new javax.swing.JLabel();
        f_sendf = new javax.swing.JFrame();
        jLabel11 = new javax.swing.JLabel();
        tf_sendf = new javax.swing.JTextField();
        b_browse = new javax.swing.JButton();
        b_sendf = new javax.swing.JButton();
        jScrollPane8 = new javax.swing.JScrollPane();
        ta_sendf = new javax.swing.JTextArea();
        jLabel12 = new javax.swing.JLabel();
        d_upcloud = new javax.swing.JDialog();
        jLabel16 = new javax.swing.JLabel();
        tf_upcloud = new javax.swing.JTextField();
        b_upcloud = new javax.swing.JButton();
        jScrollPane7 = new javax.swing.JScrollPane();
        ta_upcloud = new javax.swing.JTextArea();
        b_cbrowse = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        ta_chat = new javax.swing.JTextArea();
        tf_chat = new javax.swing.JTextField();
        b_send = new javax.swing.JButton();
        lb_username = new javax.swing.JLabel();
        lb_address = new javax.swing.JLabel();
        tf_username = new javax.swing.JTextField();
        tf_address = new javax.swing.JTextField();
        lb_port = new javax.swing.JLabel();
        lb_password = new javax.swing.JLabel();
        tf_port = new javax.swing.JTextField();
        pf_password = new javax.swing.JPasswordField();
        b_connect = new javax.swing.JButton();
        b_disconnect = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        jSeparator2 = new javax.swing.JSeparator();
        jSeparator3 = new javax.swing.JSeparator();
        jScrollPane3 = new javax.swing.JScrollPane();
        ta_oluser = new javax.swing.JTextArea();
        jLabel5 = new javax.swing.JLabel();
        jMenuBar1 = new javax.swing.JMenuBar();
        jMenu1 = new javax.swing.JMenu();
        jMenu2 = new javax.swing.JMenu();
        jMenu3 = new javax.swing.JMenu();
        mi_sendf = new javax.swing.JMenuItem();
        mi_recf = new javax.swing.JMenuItem();
        mi_cloud = new javax.swing.JMenuItem();
        mi_upcloud = new javax.swing.JMenuItem();

        fc_up.setDialogType(javax.swing.JFileChooser.CUSTOM_DIALOG);

        d_login.setAlwaysOnTop(true);
        d_login.setModal(true);

        jLabel1.setText("Username");

        jTextField1.setColumns(10);

        jLabel2.setText("Localhost");

        jTextField2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField2ActionPerformed(evt);
            }
        });

        jLabel3.setText("Password");

        jTextField3.setColumns(10);
        jTextField3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField3ActionPerformed(evt);
            }
        });

        jLabel4.setText("Socket");

        jTextField4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextField4ActionPerformed(evt);
            }
        });

        jButton1.setText("Connect");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jButton2.setText("Register");

        javax.swing.GroupLayout d_loginLayout = new javax.swing.GroupLayout(d_login.getContentPane());
        d_login.getContentPane().setLayout(d_loginLayout);
        d_loginLayout.setHorizontalGroup(
            d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_loginLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(18, 18, 18)
                .addGroup(d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jTextField2, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jTextField1, javax.swing.GroupLayout.Alignment.TRAILING))
                .addGap(30, 30, 30)
                .addGroup(d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4))
                .addGap(18, 18, 18)
                .addGroup(d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jTextField4)
                    .addComponent(jTextField3))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, d_loginLayout.createSequentialGroup()
                .addGap(49, 49, 49)
                .addComponent(jButton1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 109, Short.MAX_VALUE)
                .addComponent(jButton2)
                .addGap(48, 48, 48))
        );
        d_loginLayout.setVerticalGroup(
            d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_loginLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3))
                .addGap(18, 18, 18)
                .addGroup(d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4))
                .addGap(18, 18, 18)
                .addGroup(d_loginLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton2)
                    .addComponent(jButton1))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        d_login.getAccessibleContext().setAccessibleDescription("");
        d_login.getAccessibleContext().setAccessibleParent(this);

        d_private.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        d_private.setAlwaysOnTop(true);
        d_private.setBounds(250,250,420,400);
        d_private.setFocusTraversalPolicyProvider(true);

        ta_private.setColumns(20);
        ta_private.setEditable(false);
        ta_private.setRows(5);
        jScrollPane4.setViewportView(ta_private);

        jLabel7.setText("Enter name of user:");

        ta_poluser.setColumns(20);
        ta_poluser.setEditable(false);
        ta_poluser.setRows(5);
        jScrollPane5.setViewportView(ta_poluser);

        b_psend.setText("Send");
        b_psend.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_psendActionPerformed(evt);
            }
        });

        jLabel8.setText("Online:");

        javax.swing.GroupLayout d_privateLayout = new javax.swing.GroupLayout(d_private.getContentPane());
        d_private.getContentPane().setLayout(d_privateLayout);
        d_privateLayout.setHorizontalGroup(
            d_privateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_privateLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_privateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(d_privateLayout.createSequentialGroup()
                        .addComponent(jLabel7)
                        .addGap(18, 18, 18)
                        .addComponent(tf_receiver, javax.swing.GroupLayout.PREFERRED_SIZE, 155, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 269, Short.MAX_VALUE)
                    .addComponent(tf_private))
                .addGap(18, 18, 18)
                .addGroup(d_privateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 86, Short.MAX_VALUE)
                    .addComponent(jLabel8, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(b_psend, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addComponent(l_error, javax.swing.GroupLayout.DEFAULT_SIZE, 393, Short.MAX_VALUE)
        );
        d_privateLayout.setVerticalGroup(
            d_privateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_privateLayout.createSequentialGroup()
                .addGap(27, 27, 27)
                .addGroup(d_privateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel7)
                    .addComponent(tf_receiver, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel8))
                .addGap(18, 18, 18)
                .addGroup(d_privateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 179, Short.MAX_VALUE)
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 179, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(d_privateLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tf_private, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_psend))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(l_error, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        f_recf.setBounds(400,180,400,400);

        b_recf.setText("Receive");
        b_recf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_recfActionPerformed(evt);
            }
        });

        ta_recf.setColumns(20);
        ta_recf.setRows(5);
        jScrollPane6.setViewportView(ta_recf);

        jLabel9.setText("Select Extension:");

        cb_extension.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "pdf", "docx", "java", "jpg", "mp4", "png", "mp3", "zip", "rar", "gif", "accdb", "xml", "exe", "jar", "dll", "html", "c", "cpp", "bak", "php", "pptx", "txt", "xlsx", "psd" }));
        cb_extension.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cb_extensionActionPerformed(evt);
            }
        });

        b_target.setText("Browse");
        b_target.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_targetActionPerformed(evt);
            }
        });

        jLabel13.setText("Select sender:");

        cb_sender.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Select", "Server", "Client" }));
        cb_sender.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cb_senderActionPerformed(evt);
            }
        });

        jLabel14.setText("IP:");

        jLabel15.setText("Target:");

        javax.swing.GroupLayout f_recfLayout = new javax.swing.GroupLayout(f_recf.getContentPane());
        f_recf.getContentPane().setLayout(f_recfLayout);
        f_recfLayout.setHorizontalGroup(
            f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, f_recfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 378, Short.MAX_VALUE)
                    .addGroup(f_recfLayout.createSequentialGroup()
                        .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel9)
                            .addComponent(jLabel13)
                            .addComponent(jLabel15))
                        .addGap(18, 18, 18)
                        .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, f_recfLayout.createSequentialGroup()
                                .addComponent(cb_sender, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 42, Short.MAX_VALUE)
                                .addComponent(jLabel14)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(tf_ip, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(f_recfLayout.createSequentialGroup()
                                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(cb_extension, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(tf_setpath, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 183, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 23, Short.MAX_VALUE)
                                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addComponent(b_target, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(b_recf, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))))
                .addContainerGap())
        );
        f_recfLayout.setVerticalGroup(
            f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(f_recfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(b_recf)
                    .addComponent(jLabel9)
                    .addComponent(cb_extension, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tf_setpath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_target, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel15))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(f_recfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tf_ip, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel13)
                    .addComponent(jLabel14)
                    .addComponent(cb_sender, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 173, Short.MAX_VALUE)
                .addContainerGap())
        );

        d_cloud.setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        d_cloud.setBounds(500,180,450,400);

        ta_reccloud.setColumns(20);
        ta_reccloud.setRows(5);
        jScrollPane2.setViewportView(ta_reccloud);

        b_targetcloud.setText("Browse");
        b_targetcloud.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_targetcloudActionPerformed(evt);
            }
        });

        jLabel10.setText("File name:");

        b_download.setText("Download");
        b_download.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_downloadActionPerformed(evt);
            }
        });

        l_cloud.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        l_cloud.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                l_cloudMouseClicked(evt);
            }
        });
        jScrollPane9.setViewportView(l_cloud);

        jLabel6.setText("Target:");

        javax.swing.GroupLayout d_cloudLayout = new javax.swing.GroupLayout(d_cloud.getContentPane());
        d_cloud.getContentPane().setLayout(d_cloudLayout);
        d_cloudLayout.setHorizontalGroup(
            d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_cloudLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, d_cloudLayout.createSequentialGroup()
                        .addComponent(jScrollPane9, javax.swing.GroupLayout.DEFAULT_SIZE, 67, Short.MAX_VALUE)
                        .addGap(18, 18, 18)
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 295, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, d_cloudLayout.createSequentialGroup()
                        .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel10)
                            .addComponent(jLabel6))
                        .addGap(18, 18, 18)
                        .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(tf_target, javax.swing.GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE)
                            .addComponent(tf_cfile, javax.swing.GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(b_download, javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(b_targetcloud, javax.swing.GroupLayout.Alignment.TRAILING))))
                .addContainerGap())
        );
        d_cloudLayout.setVerticalGroup(
            d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_cloudLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel10)
                    .addComponent(tf_cfile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_download))
                .addGap(18, 18, 18)
                .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(tf_target, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(b_targetcloud))
                    .addComponent(jLabel6))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(d_cloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane2, 0, 0, Short.MAX_VALUE)
                    .addComponent(jScrollPane9, javax.swing.GroupLayout.DEFAULT_SIZE, 221, Short.MAX_VALUE))
                .addContainerGap())
        );

        f_sendf.setBounds(400,180,400,400);

        jLabel11.setText("Filename:");

        b_browse.setText("Browse");
        b_browse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_browseActionPerformed(evt);
            }
        });

        b_sendf.setText("Send");
        b_sendf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_sendfActionPerformed(evt);
            }
        });

        ta_sendf.setColumns(20);
        ta_sendf.setRows(5);
        jScrollPane8.setViewportView(ta_sendf);

        javax.swing.GroupLayout f_sendfLayout = new javax.swing.GroupLayout(f_sendf.getContentPane());
        f_sendf.getContentPane().setLayout(f_sendfLayout);
        f_sendfLayout.setHorizontalGroup(
            f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, f_sendfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane8, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)
                    .addGroup(f_sendfLayout.createSequentialGroup()
                        .addComponent(jLabel11)
                        .addGap(18, 18, 18)
                        .addComponent(tf_sendf, javax.swing.GroupLayout.PREFERRED_SIZE, 148, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(b_browse)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 38, Short.MAX_VALUE)
                        .addComponent(b_sendf)))
                .addContainerGap())
        );
        f_sendfLayout.setVerticalGroup(
            f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(f_sendfLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(f_sendfLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel11)
                    .addComponent(tf_sendf, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_browse)
                    .addComponent(b_sendf))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane8, javax.swing.GroupLayout.DEFAULT_SIZE, 237, Short.MAX_VALUE)
                .addContainerGap())
        );

        jLabel12.setText("Ip:");

        jLabel16.setText("File name:");

        b_upcloud.setText("Upload");
        b_upcloud.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_upcloudActionPerformed(evt);
            }
        });

        ta_upcloud.setColumns(20);
        ta_upcloud.setRows(5);
        jScrollPane7.setViewportView(ta_upcloud);

        b_cbrowse.setText("Browse");
        b_cbrowse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_cbrowseActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout d_upcloudLayout = new javax.swing.GroupLayout(d_upcloud.getContentPane());
        d_upcloud.getContentPane().setLayout(d_upcloudLayout);
        d_upcloudLayout.setHorizontalGroup(
            d_upcloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_upcloudLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_upcloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane7, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)
                    .addGroup(d_upcloudLayout.createSequentialGroup()
                        .addComponent(jLabel16)
                        .addGap(18, 18, 18)
                        .addComponent(tf_upcloud, javax.swing.GroupLayout.PREFERRED_SIZE, 134, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(b_cbrowse)
                        .addGap(18, 18, 18)
                        .addComponent(b_upcloud, javax.swing.GroupLayout.DEFAULT_SIZE, 76, Short.MAX_VALUE)))
                .addContainerGap())
        );
        d_upcloudLayout.setVerticalGroup(
            d_upcloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(d_upcloudLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(d_upcloudLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel16)
                    .addComponent(tf_upcloud, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(b_upcloud)
                    .addComponent(b_cbrowse))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane7, javax.swing.GroupLayout.DEFAULT_SIZE, 237, Short.MAX_VALUE)
                .addContainerGap())
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Chat - Client's frame");
        setName("client"); // NOI18N
        setResizable(false);

        ta_chat.setColumns(20);
        ta_chat.setEditable(false);
        ta_chat.setRows(5);
        jScrollPane1.setViewportView(ta_chat);

        b_send.setText("SEND");
        b_send.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_sendActionPerformed(evt);
            }
        });

        lb_username.setText("Username :");

        lb_address.setText("Address : ");

        tf_username.setText("Hatsu");
        tf_username.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tf_usernameActionPerformed(evt);
            }
        });

        tf_address.setText("192.168.0.103");
        tf_address.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tf_addressActionPerformed(evt);
            }
        });

        lb_port.setText("Port :");

        lb_password.setText("Password : ");

        tf_port.setText("2222");
        tf_port.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tf_portActionPerformed(evt);
            }
        });

        pf_password.setText("1234");

        b_connect.setText("Connect");
        b_connect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_connectActionPerformed(evt);
            }
        });

        b_disconnect.setText("Disconnect");
        b_disconnect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                b_disconnectActionPerformed(evt);
            }
        });

        jSeparator3.setOrientation(javax.swing.SwingConstants.VERTICAL);

        ta_oluser.setColumns(20);
        ta_oluser.setEditable(false);
        ta_oluser.setRows(10);
        ta_oluser.setAutoscrolls(false);
        jScrollPane3.setViewportView(ta_oluser);

        jLabel5.setText("Online Users");

        jMenu1.setText("File");
        jMenuBar1.add(jMenu1);

        jMenu2.setText("Edit");
        jMenuBar1.add(jMenu2);

        jMenu3.setText("Resources");

        mi_sendf.setText("Send File");
        mi_sendf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_sendfActionPerformed(evt);
            }
        });
        jMenu3.add(mi_sendf);

        mi_recf.setText("Receive File");
        mi_recf.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_recfActionPerformed(evt);
            }
        });
        jMenu3.add(mi_recf);

        mi_cloud.setText("Cloud");
        mi_cloud.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_cloudActionPerformed(evt);
            }
        });
        jMenu3.add(mi_cloud);

        mi_upcloud.setText("Upload to cloud");
        mi_upcloud.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                mi_upcloudActionPerformed(evt);
            }
        });
        jMenu3.add(mi_upcloud);

        jMenuBar1.add(jMenu3);

        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 480, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(lb_address, javax.swing.GroupLayout.PREFERRED_SIZE, 62, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(tf_address, javax.swing.GroupLayout.PREFERRED_SIZE, 91, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(lb_port, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(72, 72, 72))
                                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                                        .addComponent(lb_username, javax.swing.GroupLayout.PREFERRED_SIZE, 62, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(10, 10, 10)
                                        .addComponent(tf_username, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(lb_password)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(tf_port, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(pf_password, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(21, 21, 21))
                            .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 371, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(16, 16, 16)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(b_connect, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(b_disconnect, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(tf_chat, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 351, Short.MAX_VALUE)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 351, Short.MAX_VALUE))
                        .addGap(10, 10, 10)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane3, 0, 0, Short.MAX_VALUE)
                            .addComponent(jLabel5)
                            .addComponent(b_send, javax.swing.GroupLayout.DEFAULT_SIZE, 119, Short.MAX_VALUE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(lb_address)
                            .addComponent(lb_port)
                            .addComponent(tf_address, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(b_connect)
                            .addComponent(tf_port, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(8, 8, 8)
                        .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(lb_username)
                            .addComponent(lb_password)
                            .addComponent(tf_username, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(pf_password, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(b_disconnect)))
                    .addComponent(jSeparator3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(4, 4, 4)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 262, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 127, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 25, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(tf_chat, javax.swing.GroupLayout.DEFAULT_SIZE, 24, Short.MAX_VALUE)
                    .addComponent(b_send, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        setBounds((screenSize.width-516)/2, (screenSize.height-507)/2, 516, 507);
    }// </editor-fold>//GEN-END:initComponents

    private void b_sendActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_sendActionPerformed
        String nothing = "";
        
        
            if ((tf_chat.getText()).equals(nothing)) 
            {
                tf_chat.setText("");
                tf_chat.requestFocus();
            } 
            else 
            {
                try 
                {
                    
                    encrypt=encryptText(username + ":" + tf_chat.getText() + ":" + "Chat");
                    writer.println(encrypt);
                    writer.flush(); // flushes the buffer
                } 
                catch (Exception ex) {ta_chat.append("Message was not sent. \n");}
                
                tf_chat.setText("");
                tf_chat.requestFocus();
                
            }
        
        

    }//GEN-LAST:event_b_sendActionPerformed

    private void b_disconnectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_disconnectActionPerformed
        sendDisconnect();
        Disconnect();
    }//GEN-LAST:event_b_disconnectActionPerformed

    private void b_connectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_connectActionPerformed
        if (isConnected == false)
        {
            username = tf_username.getText();
            password = pf_password.getText();
            tf_username.setEditable(false);
            pf_password.setEditable(false);
            address = tf_address.getText();
            port = Integer.parseInt(tf_port.getText());
            
            try
            {
                sock = new Socket(address, port);
                InputStreamReader streamreader = new InputStreamReader(sock.getInputStream());
                reader = new BufferedReader(streamreader);
                writer = new PrintWriter(sock.getOutputStream());
                is = (sock.getInputStream());
                encrypt=encryptText(username + ":has connected.:Connect:"+password);
                writer.println(encrypt);
                writer.flush();
                isConnected = true;
            }
            catch (Exception ex)
            {
                ta_chat.append("Cannot Connect! Try Again. \n");
                tf_username.setEditable(true);
                pf_password.setEditable(true);
            }

            ListenThread();
//capture a=new capture();
        //a.start();
        } 
        else if (isConnected == true)
        {
            ta_chat.append("You are already connected. \n");
        }
        
    }//GEN-LAST:event_b_connectActionPerformed

    private void tf_portActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_portActionPerformed

    }//GEN-LAST:event_tf_portActionPerformed

    private void tf_usernameActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_usernameActionPerformed

    }//GEN-LAST:event_tf_usernameActionPerformed

    private void tf_addressActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tf_addressActionPerformed

    }//GEN-LAST:event_tf_addressActionPerformed

    private void mi_sendfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_sendfActionPerformed
       
        f_sendf.setVisible(true);
        
    }//GEN-LAST:event_mi_sendfActionPerformed

    private void mi_recfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_recfActionPerformed
        f_recf.setVisible(true);
    }//GEN-LAST:event_mi_recfActionPerformed

private void jTextField2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField2ActionPerformed
// TODO add your handling code here:
}//GEN-LAST:event_jTextField2ActionPerformed

private void jTextField4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField4ActionPerformed
// TODO add your handling code here:
}//GEN-LAST:event_jTextField4ActionPerformed

private void jTextField3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField3ActionPerformed
// TODO add your handling code here:
}//GEN-LAST:event_jTextField3ActionPerformed

private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
// TODO add your handling code here:
}//GEN-LAST:event_jButton1ActionPerformed

private void b_psendActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_psendActionPerformed

    
}//GEN-LAST:event_b_psendActionPerformed

    private void b_recfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_recfActionPerformed
        try {
            receiveFile();
        } catch (IOException ex) {
        }
    
    
    }//GEN-LAST:event_b_recfActionPerformed

    private void b_targetActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_targetActionPerformed
        JFileChooser chooser= new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.showOpenDialog(null);
        tf_setpath.setText(chooser.getSelectedFile().getAbsolutePath());
    }//GEN-LAST:event_b_targetActionPerformed

    private void mi_cloudActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_cloudActionPerformed
        try {
            String str= username + ":Cloud:Cloud";
            encrypt=encryptText(str);
            writer.println(encrypt);
            writer.flush();
            d_cloud.setVisible(true);
        } catch (Exception ex) {
        }
        
    }//GEN-LAST:event_mi_cloudActionPerformed

    private void b_downloadActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_downloadActionPerformed
        if(!"".equals(tf_target.getText()))
        {
            String str=tf_cfile.getText();
        String FILE_TO_RECEIVED2 = tf_target.getText() + "\\" + str;
        int FILE_SIZE2=6022386;
        
        int bytesRead;
    int current = 0;
    FileOutputStream fos = null;
    BufferedOutputStream bos = null;
    Socket sock2 = null;
    try {
      sock2 = new Socket(address,2223);
      byte [] mybytearray  = new byte [FILE_SIZE2];
      InputStream is2 = sock2.getInputStream();
      fos = new FileOutputStream(FILE_TO_RECEIVED2);
      bos = new BufferedOutputStream(fos);
      bytesRead = is2.read(mybytearray,0,mybytearray.length);
      current = bytesRead;

      do {
         bytesRead =
            is2.read(mybytearray, current, (mybytearray.length-current));
         if(bytesRead >= 0) current += bytesRead;
      } while(bytesRead > -1);

      bos.write(mybytearray, 0 , current);
      bos.flush();
      ta_reccloud.append("File " + FILE_TO_RECEIVED2 + " downloaded (" + current + " bytes read)\n");
    }
        catch (UnknownHostException ex) {
        } catch (IOException ex) {
        }    finally {
            try {
                if (fos != null) fos.close();
                if (bos != null) bos.close();
                if (sock2 != null) sock2.close();
            } catch (IOException ex) {
            }
    }
    }
        else
            tf_setpath.setText("Select path");
    }//GEN-LAST:event_b_downloadActionPerformed

    private void b_targetcloudActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_targetcloudActionPerformed
        JFileChooser chooser= new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.showOpenDialog(null);
        tf_target.setText(chooser.getSelectedFile().getAbsolutePath());
    }//GEN-LAST:event_b_targetcloudActionPerformed

private void b_browseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_browseActionPerformed
    JFileChooser chooser = new JFileChooser();
        chooser.showOpenDialog(null);
        sendf=chooser.getSelectedFile();
        tf_sendf.setText(sendf.getAbsolutePath());
}//GEN-LAST:event_b_browseActionPerformed

private void b_sendfActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_sendfActionPerformed

    
            try {
                    sendf(sendf);
                } catch (IOException ex) {
                }
        
}//GEN-LAST:event_b_sendfActionPerformed

private void cb_extensionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cb_extensionActionPerformed
// TODO add your handling code here:
}//GEN-LAST:event_cb_extensionActionPerformed

private void cb_senderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cb_senderActionPerformed
String ipselect;
        ipselect = (String)cb_sender.getSelectedItem();
        if(ipselect.equals("Server"))
            tf_ip.setText(address);
        if(ipselect.equals("Client"))
            tf_ip.setText("");
        
        // TODO add your handling code here:
}//GEN-LAST:event_cb_senderActionPerformed

    private void l_cloudMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_l_cloudMouseClicked
        String fname= (String) l_cloud.getSelectedValue();
        tf_cfile.setText(fname);
        try {
            encrypt=encryptText(username + ":" + tf_cfile.getText() + ":SendCloud");
           // l_cloud.setEnable(false);
        } catch (Exception ex) {
        }
                    writer.println(encrypt);
                    writer.flush();
    }//GEN-LAST:event_l_cloudMouseClicked

    private void b_cbrowseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_cbrowseActionPerformed
        JFileChooser chooser = new JFileChooser();
        chooser.showOpenDialog(null);
        sendf=chooser.getSelectedFile();
        tf_upcloud.setText(sendf.getAbsolutePath());
        filename=chooser.getSelectedFile().getName();
        
    }//GEN-LAST:event_b_cbrowseActionPerformed

    private void mi_upcloudActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_mi_upcloudActionPerformed
        d_upcloud.setVisible(true);
        
    }//GEN-LAST:event_mi_upcloudActionPerformed

    private void b_upcloudActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_b_upcloudActionPerformed
        try {
            
            encrypt=encryptText(username + ":" + filename + ":" + "ReceiveCloud:" + InetAddress.getLocalHost().getHostAddress());
                        writer.println(encrypt);
                        writer.flush();
        } catch (Exception ex) {
        }
        try {
            upcloud(sendf);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }//GEN-LAST:event_b_upcloudActionPerformed

    public static void main(String args[]) 
    {
        Path path1,path2,path3,path4;
        File dir1;
        path1 = FileSystems.getDefault().getPath("D:\\Cloud Client");
        path2 = FileSystems.getDefault().getPath("D:\\Cloud Client\\Screenshots");
        path3 = FileSystems.getDefault().getPath("D:\\Cloud Client\\Logs");
        if(Files.notExists(path1))
                {
                    dir1=new File("D:\\Cloud Client");
                    Boolean mk=dir1.mkdir();
                }
            if(Files.notExists(path2))
                {
                    dir1=new File("D:\\Cloud Client\\Screenshots");
                    Boolean mk=dir1.mkdir();
                }
            if(Files.notExists(path3))
                {
                    dir1=new File("D:\\Cloud Client\\Logs");
                    Boolean mk=dir1.mkdir();
                }
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
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(client_frame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        java.awt.EventQueue.invokeLater(new Runnable() 
        {
            @Override
            public void run() 
            {
                
                new client_frame().setVisible(true);
            }
        });
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton b_browse;
    private javax.swing.JButton b_cbrowse;
    private javax.swing.JButton b_connect;
    private javax.swing.JButton b_disconnect;
    private javax.swing.JButton b_download;
    private javax.swing.JButton b_psend;
    private javax.swing.JButton b_recf;
    private javax.swing.JButton b_send;
    private javax.swing.JButton b_sendf;
    private javax.swing.JButton b_target;
    private javax.swing.JButton b_targetcloud;
    private javax.swing.JButton b_upcloud;
    private javax.swing.JComboBox cb_extension;
    private javax.swing.JComboBox cb_sender;
    private javax.swing.JDialog d_cloud;
    private javax.swing.JDialog d_login;
    private javax.swing.JDialog d_private;
    private javax.swing.JDialog d_upcloud;
    private javax.swing.JFrame f_recf;
    private javax.swing.JFrame f_sendf;
    private javax.swing.JFileChooser fc_up;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel13;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
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
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JScrollPane jScrollPane7;
    private javax.swing.JScrollPane jScrollPane8;
    private javax.swing.JScrollPane jScrollPane9;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JSeparator jSeparator3;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    private javax.swing.JTextField jTextField4;
    private javax.swing.JList l_cloud;
    private javax.swing.JLabel l_error;
    private javax.swing.JLabel lb_address;
    private javax.swing.JLabel lb_password;
    private javax.swing.JLabel lb_port;
    private javax.swing.JLabel lb_username;
    private javax.swing.JMenuItem mi_cloud;
    private javax.swing.JMenuItem mi_recf;
    private javax.swing.JMenuItem mi_sendf;
    private javax.swing.JMenuItem mi_upcloud;
    private javax.swing.JPasswordField pf_password;
    private javax.swing.JTextArea ta_chat;
    private javax.swing.JTextArea ta_oluser;
    private javax.swing.JTextArea ta_poluser;
    private javax.swing.JTextArea ta_private;
    private javax.swing.JTextArea ta_reccloud;
    private javax.swing.JTextArea ta_recf;
    private javax.swing.JTextArea ta_sendf;
    private javax.swing.JTextArea ta_upcloud;
    private javax.swing.JTextField tf_address;
    private javax.swing.JTextField tf_cfile;
    private javax.swing.JTextField tf_chat;
    private javax.swing.JTextField tf_ip;
    private javax.swing.JTextField tf_port;
    private javax.swing.JTextField tf_private;
    private javax.swing.JTextField tf_receiver;
    private javax.swing.JTextField tf_sendf;
    private javax.swing.JTextField tf_setpath;
    private javax.swing.JTextField tf_target;
    private javax.swing.JTextField tf_upcloud;
    private javax.swing.JTextField tf_username;
    // End of variables declaration//GEN-END:variables
}
