/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.net.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.util.*;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/*
 * The Client that can be run both as a console or a GUI
 */
public class Client  {

	Cipher c;
        X509Certificate cert,certSLoad,certS;  //dhlwsh pistopoihtikwn pou 8a ginoun load apo keystore,truststore
        Signature sig;
        MessageDigest md;
        KeyStore ks;
        private ObjectInputStream sInput;		// to read from the socket
	private ObjectOutputStream sOutput;		// to write on the socket
	private Socket socket;
        private SimpleDateFormat sdf;  
        final private String KSpass="keystore2pass";//kwdikos keystore tou client2
        final private String PrKeypass="client2pass";//kwdikos privatekey tou client2
        final private String TSpass="truststore2pass"; //kwdikos truststore tou client2
        private  PublicKey PubKeyS;
        private  PrivateKey PrivKey;
	private ClientGUI cg;
	private String server, username;
	private int port;
        final String name="Client2";   //onoma pou ginetai h anagnwrish apo ton server
        
        
	Client(String server, int port, String username) {
		// which calls the common constructor with the GUI set to null
		this(server, port, username, null);
	}

	/*
	 * Constructor call when used from a GUI
	 * in console mode the ClienGUI parameter is null
	 */
	Client(String server, int port, String username, ClientGUI cg) {
		this.server = server;
		this.port = port;
		this.username = username;
		// save if we are in GUI mode or not
		this.cg = cg;
	}
	
	/*
	 * To start the dialog
	 */
	public boolean start() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException, ClassNotFoundException {
		// try to connect to the server
		try {
			socket = new Socket(server, port);
		} 
		// if it failed not much I can so
		catch(Exception ec) {
			display("Error connectiong to server:" + ec);
			return false;
		}
		
		String msg = "Connection accepted " + socket.getInetAddress() + ":" + socket.getPort();
		display(msg + '\n');
	        
                c=Cipher.getInstance("RSA/ECB/PKCS1Padding");   //arxikopohsh tou antikeimenou cipher c
                ks= KeyStore.getInstance("JKS");             //arxikopoihsh tou antikeimenou KeyStore ks
                ks.load(new FileInputStream("C:\\keystore2.jks"),KSpass.toCharArray());   //fortwsh tou keystore2 sto ks
                cert = (X509Certificate)ks.getCertificate("Client2");              //certificate tou Client2
                PrivKey=(PrivateKey) ks.getKey("Client2", PrKeypass.toCharArray());  //private key tou Client2
                 ks.load(new FileInputStream("C:\\truststore2.jks"),TSpass.toCharArray());  //fortwsh tou truststore tou client2
                certSLoad=(X509Certificate) ks.getCertificate("Server");     //certificate tou server(argotera elegxetai h taytopoihsh,otan ginetai h syndesh)
                PubKeyS=certSLoad.getPublicKey();  //publickey tou server
		/* Creating both Data Stream */
                
		try
		{
			sInput  = new ObjectInputStream(socket.getInputStream());
			sOutput = new ObjectOutputStream(socket.getOutputStream());
		}
		catch (IOException eIO) {
			display("Exception creating new Input/output Streams: " + eIO);
			return false;
		}

		// creates the Thread to listen from the server 
		new ListenFromServer().start();
		// Send our username to the server this is the only message that we
		// will send as a String. All other messages will be ChatMessage objects
		try
		{
                    sOutput.writeObject(new ChatMessage(username,cert,name));
                   
			//sOutput.writeObject(username);
                        //certS2=(Certificate)sInput.readObject();
                        //PubKeyS=certS2.getPublicKey();
                }
		catch (IOException eIO) {
			display("Exception doing login : " + eIO);
			disconnect();
			return false;
		}
		// success we inform the caller that it worked
		return true;
	}

	/*
	 * To send a message to the console or the GUI
	 */
	private void display(String msg) {
		if(cg == null)
			System.out.print(msg);      // println in console mode
		else
			cg.append(msg);		// append to the ClientGUI JTextArea (or whatever)
	}
	
	/*
	 * To send a message to the server
	 */
	void sendMessage(ChatMessage msg) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException, CertificateException, NoSuchProviderException {
		try {
                    
                       certSLoad.checkValidity();
                       if(msg.getType()==1){
                           
                            String s=msg.getMessage();
                            //Digital signature
                            byte[] sign1=DigitalSign(s,PrivKey);
                            
                            sdf=new SimpleDateFormat();
                            String time  = sdf.format(new Date());
                            String messageLf = time + ": " + s + "\n";
                           if(!(cg==null)){
                              display("> "+messageLf);
                            }
                            //encrypt
                            byte[] kript = encrypt(s,PubKeyS);
                            
                            //Digest
                            byte[] sinopsi =Digest(s);
                            //apostoli minimatos
                            ChatMessage cm = new ChatMessage(1,kript,sinopsi,sign1,username,name);
//                            cg.append(msg.getMessage());
                            
                            sOutput.writeObject(cm);
                       }
                       else{
                           sOutput.writeObject(msg);
                       }
                        //    display("kripto tou 1");
			//sOutput.writeObject(msg);
		}
		catch(IOException e) {
			display("Exception writing to server: " + e);
		}
	}

	/*
	 * When something goes wrong
	 * Close the Input/Output streams and disconnect not much to do in the catch clause
	 */
	private void disconnect() {
		try { 
			if(sInput != null) sInput.close();
		}
		catch(Exception e) {} // not much else I can do
		try {
			if(sOutput != null) sOutput.close();
		}
		catch(Exception e) {} // not much else I can do
        try{
			if(socket != null) socket.close();
		}
		catch(Exception e) {} // not much else I can do
		
		// inform the GUI
		if(cg != null)
			cg.connectionFailed();
			
	}
        
           private byte[] encrypt(String text,PublicKey pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
            byte[] aplo = text.getBytes();                            
                            c=Cipher.getInstance("RSA/ECB/PKCS1Padding");
                           c.init(Cipher.ENCRYPT_MODE,pk);
                            byte[] kript = c.doFinal(aplo);
                            return kript;
        }
        
        private String decrypt(byte[] cipher,PrivateKey pk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
            c=Cipher.getInstance("RSA/ECB/PKCS1Padding");
                 c.init(Cipher.DECRYPT_MODE,pk);                                       
                byte[] apokript = c.doFinal(cipher);
                String text=new String(apokript);
                return text;
        }
        
        private byte[] Digest(String text) throws NoSuchAlgorithmException{
             md = MessageDigest.getInstance("SHA-256");
             md.update(text.getBytes());
             byte[] sinopsi = md.digest();
             return sinopsi;
        }
        
        private byte[] DigitalSign(String text,PrivateKey pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
             sig=Signature.getInstance("SHA256withRSA");
             sig.initSign(pk);
             sig.update(text.getBytes());
             byte[] sign=sig.sign();
             return sign;
        }
        
        private boolean VerifySignature(String text1,byte[] signature,PublicKey pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
             sig=Signature.getInstance("SHA256withRSA");
              sig.initVerify(pk); 
              sig.update(text1.getBytes());
              return sig.verify(signature);
        }
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException, SignatureException, NoSuchProviderException {
		// default values
		int portNumber = 1500;
                Scanner usernamescan = new Scanner(System.in);
                System.out.print("Enter your username: ");
                String userName=usernamescan.nextLine();
		String serverAddress = "localhost";
		//String userName ="Anonymous";  

		// depending of the number of arguments provided we fall through
		switch(args.length) {
			// > javac Client username portNumber serverAddr
			case 3:
				serverAddress = args[2];
			// > javac Client username portNumber
			case 2:
				try {
					portNumber = Integer.parseInt(args[1]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Client [username] [portNumber] [serverAddress]");
					return;
				}
			// > javac Client username
			case 1: 
				userName = args[0];
			// > java Client
			case 0:
				break;
			// invalid number of arguments
			default:
				System.out.println("Usage is: > java Client [username] [portNumber] {serverAddress]");
			return;
		}
		// create the Client object
		Client client = new Client(serverAddress, portNumber, userName);
		// test if we can start the connection to the Server
		// if it failed nothing we can do
		if(!client.start())
			return;
		
		// wait for messages from user
		Scanner scan = new Scanner(System.in);
		// loop forever for message from the user
		while(true) {
			System.out.print("> ");
			// read message from user
			String msg = scan.nextLine();
			// logout if message is LOGOUT
			if(msg.equalsIgnoreCase("LOGOUT")) {
				client.sendMessage(new ChatMessage(ChatMessage.LOGOUT, ""));
				// break to do the disconnect
				break;
			}
			// message WhoIsIn
			else if(msg.equalsIgnoreCase("WHOISIN")) {
				client.sendMessage(new ChatMessage(ChatMessage.WHOISIN, ""));				
			}
			else {		
                            
                                  // default to ordinary message
                                
				client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, msg));
			}
		}
		// done disconnect
		client.disconnect();	
	}

	/*
	 * a class that waits for the message from the server and append them to the JTextArea
	 * if we have a GUI or simply System.out.println() it in console mode
	 */
	class ListenFromServer extends Thread {
          ChatMessage  cm;
      //    boolean eqPub=true;
		public void run() {
              try {
                  certS = (X509Certificate) sInput.readObject(); //dexomaste to pistopoihtiko tou server
   
                  certSLoad.verify(certS.getPublicKey());
                  
              } catch (IOException ex) {
                  Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
              } catch (ClassNotFoundException ex) {
                  Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
              } catch (CertificateException ex) {
                  Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
              } catch (NoSuchAlgorithmException ex) {
                  Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
              } catch (InvalidKeyException ex) {
                  Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                  display("Server failed to authenticate");
              } catch (NoSuchProviderException ex) {
                  Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
              } catch (SignatureException ex) {
                  Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
              }
			while(true) {
				try {
                               cm  = (ChatMessage) sInput.readObject();  // dexetai minima typou ChatMessage apo ton Server
                            if(cm.getType()==1){    // an einai minima keimenou
                              //  certSLoad.verify(certS.getPublicKey());  //elegxos gia to an ta publickeys einai idia(tou fortwmenou apo truststore kai aytou pou lavame)
                                certSLoad.checkValidity();  //elegxos gia to an to pistopoihtiko exei lhksei
                                         byte[] kript = cm.getBit();  //pairnoume to kriprografimeno minima
                                        
                                       //decryption                                                                            
                                        String msg = decrypt(kript,PrivKey);  
                                       
                                         
                                        sdf = new SimpleDateFormat();
                                        String time = sdf.format(new Date());
                                        String messageLf = time +" "+cm.getUsername()+ ": " + msg + "\n";
                                         //Digest
                                         byte[] sinopsi = Digest(msg);
                                        
                                    if((MessageDigest.isEqual(sinopsi,cm.getDig())) && (VerifySignature(msg,cm.getSign(),PubKeyS))){ // an i sinopsi kai i psifiaki ypografh einai ok proxwrame sthn emfanish tou minimatos
                                       
					      
		                        if(cg == null) {
						System.out.print(messageLf);
						System.out.print("> ");
					}
					else {
						cg.append(messageLf);
                                                //cg.append("\n");
					}
                                         
                            }else{
                                        display("Digests are not equal or Signature cannot be verified");
                                    }
                                  
                            }
                          else if(cm.getType()==2){ //to minima einai typou WHOISIN
                                               if(cg == null) {
						System.out.println(cm.getMessage());
						System.out.print("> ");
					}
					else {
						cg.append(cm.getMessage());
					}
                                 }
				}
				catch(IOException e) {
					display("Server has close the connection: " + e + '\n');
					if(cg != null) 
						cg.connectionFailed();
					break;
				}
				// can't happen with a String object but need the catch anyhow
				catch(ClassNotFoundException e2) {
				} catch (IllegalBlockSizeException ex) {
                                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (BadPaddingException ex) {
                                display("Decryption Failed");
                                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (InvalidKeyException ex) {
                                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (NoSuchAlgorithmException ex) {
                                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (NoSuchPaddingException ex) {
                                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (SignatureException ex) {
                                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (CertificateException ex) {
                                display("Authentication failed.");
                                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                            }
			}
		}
	}
}

