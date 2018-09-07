
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.Security;
import java.io.*;

public class client extends Frame implements ActionListener, Runnable
{
        Image Icon = Toolkit.getDefaultToolkit().getImage("hi.gif") ;
	Socket s;
	BufferedReader br;
	BufferedWriter bw;
	TextField text;
        Button sendBut, exitBut;
	List list;
    OakleyInitiator oi;
    SecretKey desKey;
    double SecretValue;
    static String serverName;

        public client(String st)
	{
                super(st);
                setSize(500, 260);
		setIconImage(Icon);
		setLocation(400,300);
                setResizable(false);
                setBackground(new Color(192, 192, 192));
		this.setLayout(new GridLayout(2, 1));

                Panel panels[] = new Panel[2];
                panels[0] = new Panel();
                panels[1] = new Panel();
                panels[0].setLayout(new BorderLayout());
                panels[1].setLayout(new FlowLayout(FlowLayout.LEFT));

                sendBut = new Button("Send");
                exitBut = new Button("Exit");

                sendBut.addActionListener(this);
                exitBut.addActionListener(this);

                list = new List();
		text = new TextField(50);

                panels[0].add(list);
                panels[1].add(text);
                panels[1].add(sendBut);
                panels[1].add(exitBut);     


                add(panels[0]);
                add(panels[1]);

		setVisible(true);

                try
                {
                        /* Assuming that this application is run on single
                        machine I've used the default ip i.e., 127.0.0.1. If
                        you want to use it on 2 different machines use the
                        ip that is assigned to the machine on which server
                        applicatin is residing*/


                        s = new Socket(serverName, 1053);
                        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
                        bw = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));


                        OutputStreamWriter bosw=new OutputStreamWriter(s.getOutputStream());
                        String cA="1";
                        String nA="3";


                        SecretValue=CommonFunctions.generateRandom();
                        oi=new OakleyInitiator(1,2,SecretValue);
                        System.err.println("Message 1 sent by oakley initiator:");
                        System.out.println(oi.sendMsg1());
                        bw.write(oi.sendMsg1());
                        bw.newLine();
                        bw.flush();
			Thread th;
			th = new Thread(this);
			th.start();
			
		}catch(Exception e){}
		
	}

        public static void main(String arg[])
	{
                // create an object instance of the class
                // by sending the title as parameter
            serverName = arg[0];
        	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                new client("Chat Client Application");
		
	}

        public void run()
	{
            boolean done=false;
                while (true && !done)
		{
			try
                        {
                            char[] line=new char[2000];
                        	br.read(line);
//                        	System.out.println(line);
                        	boolean temp=oi.authenticateMsg2(line);
                        	if(temp)
                        	{
                        		System.out.println("authenticated msg2!");
                        		list.add("authenticated msg2!");
                                done=true;
                                desKey=oi.getDESKey();
                                System.err.println("Third Message in oakley exchange :");
                                String msg=oi.sendMsg3(line);
                                System.out.println(msg);
                                bw.write(msg);
                                bw.newLine();
                                bw.flush();
//                                list.add(line.toString());
                            }
                            else
                            {
                                System.out.println("authentication failed!");
                                list.add("authentication failed!");
                                //pout and exit
                            }

            if(done)
                while(true)
                {
                    char[] tempLine=new char[300];
                    br.read(tempLine);
                    String tempString=new String(tempLine);
                    if(tempString.indexOf('\0')!=-1)
                        tempString=tempString.substring(0,tempString.indexOf('\0'));
                    System.err.println("Encrypted string received from server is : ");
                    System.out.println(tempString);
                    byte[] lineBytes=new sun.misc.BASE64Decoder().decodeBuffer(tempString);
                    byte[] decoded=DES.crypt(lineBytes,Cipher.DECRYPT_MODE,desKey);
                    String finalLine=new String(decoded);
                    list.add("Server : "+ finalLine);
                    System.err.println("Decrypted text is : ");
                    System.out.println(finalLine);
//                    list.add("Server : "+ br.readLine());
                }
                }catch (Exception e){}
		}
	}
	

        public void actionPerformed(ActionEvent ae)
	{
                 if(ae.getSource().equals(exitBut))
			 System.exit(0);
		 else
                 {
                        try
                        {
                                byte[] in_bytes=text.getText().getBytes();
                                byte[] encoded=DES.crypt(in_bytes,Cipher.ENCRYPT_MODE,desKey);
                                String finalLine=new sun.misc.BASE64Encoder().encode(encoded);
                                bw.write(finalLine);
//                                bw.write(text.getText());
                                list.add("Client : "+text.getText());
                                bw.newLine();
                                bw.flush();
                                text.setText("");
                        }catch(Exception m){}
		 }
				  
	}
	
}
