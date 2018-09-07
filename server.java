
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.awt.*;
import java.awt.event.*;
import java.net.*;
import java.security.Security;
import java.security.KeyPair;
import java.io.*;

public class server extends Frame implements ActionListener, Runnable
{
        Image Icon = Toolkit.getDefaultToolkit().getImage("hi.gif");
        ServerSocket ss;
        Socket s;
	BufferedReader br;
	BufferedWriter bw;
	TextField text;
    Button sendBut, exitBut;
    List list;
    SecretKey desKey;
    double SecretValue;

    public server(String m) // class constructor
	{
                super(m);
                setSize(500, 260);
                setLocation(0,0);
                setIconImage(Icon);
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
                list.add("Server up & Listening on port plz wait...");

                text = new TextField(50);

                panels[0].add(list);
                panels[1].add(text);
                panels[1].add(sendBut);
                panels[1].add(exitBut);     

                add(panels[0]);
                add(panels[1]);

                setVisible(true);

                SecretValue=CommonFunctions.generateRandom();

                try
                {
                        ss = new ServerSocket(1053);//some port number, better be above 1000
                        s = ss.accept();
                        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
                        bw = new BufferedWriter(new OutputStreamWriter(s.getOutputStream()));
//                        bw.write("Hi! ASL plz??");
//                        bw.newLine();
//                        bw.flush();
                        Thread th;
                        th = new Thread(this);
                        th.start();
			 
			
		}catch(Exception e){}

	}

        public void run()
	{

      	OakleyResponder or;
        boolean done=false;
        while (true && !done)
		{
                        try
                        {
                            char[] line=new char[1000];
                        	br.read(line);
//                        	System.out.println(line);

                            or=new OakleyResponder(2,SecretValue);
                        	boolean temp=or.authenticateMsg1(line);
                        	if(temp)
                        	{
                        		System.out.println("authenticated msg1!");
                        		list.add("authenticated msg1!");
                                System.err.println("Second message in oakley exchange is :");
                                String msg=or.sendMsg2(line);
                                System.out.println(msg);
                                bw.write(msg);
                                bw.newLine();
                                bw.flush();
                                while(true && !done)
                                {
                                    char[] line1=new char[2000];
                        	        br.read(line1);
//                        	        System.out.println(line1);
                        	        boolean temp1=or.authenticateMsg3(line1);
                        	        if(temp1)
                                    {
                                        System.out.println("authenticated msg3!");
                                        list.add("authenticated msg3!");
                                        desKey=or.getDESKey();
                                        done = true;
                                    }
                                    else
                                    {
                                        //pout and exit
                                    }
                                }
                            }
                        	else
                        	{
                        		System.out.println("authentication failed!");
                        		list.add("authentication failed!");
                                //Also remember to pout and exit
                        	}
//                        	list.add(line.toString());


            if(done)
            {
                while(true)
                {
                    char[] tempLine=new char[300];
                    br.read(tempLine);
                    String tempString=new String(tempLine);
                    if(tempString.indexOf('\0')!=-1)
                        tempString=tempString.substring(0,tempString.indexOf('\0'));
                    System.err.println("Length of encrypted String received from client is :" + tempString.length());
                    System.err.println("And the ecrypted string is :");
                    System.out.println(tempString);
                    byte[] lineBytes=new sun.misc.BASE64Decoder().decodeBuffer(tempString);
                    byte[] decoded=DES.crypt(lineBytes,Cipher.DECRYPT_MODE,desKey);
                    String finalLine=new String(decoded);
//                    list.add("Client : "+br.readLine());
                    System.err.println("Decrypted text is : ");
                    System.out.println(finalLine);
                    list.add("Client : "+finalLine);
                }
            }
         }catch (Exception e){}
		}
	}

        public static void main(String arg[])
	{
                // create an object instance
                // by sending the title as a parameter
        	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            new server("Chat Server Applicaton");
	}
	
        public void actionPerformed(ActionEvent ae)
	{
                 if (ae.getSource().equals(exitBut))
			 System.exit(0);
                 else
                 {
                        try
                        {
                                byte[] in_bytes=text.getText().getBytes();
                                byte[] encoded=DES.crypt(in_bytes,Cipher.ENCRYPT_MODE,desKey);
                                String finalLine=new sun.misc.BASE64Encoder().encode(encoded);
                                bw.write(finalLine);
                                list.add("Server : "+text.getText());
                                bw.newLine();bw.flush();
                                text.setText("");
                        }catch(Exception x){}
		 }
				  
	}
	
}
