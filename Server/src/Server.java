/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.io.*;
import java.net.*;
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
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
/*
 * The server that can be run both as a console application or a GUI
 */
public class Server {
	// a unique ID for each connection
	private static int uniqueId;
	// an ArrayList to keep the list of the Client
	private ArrayList<ClientThread> al;
	// if I am in a GUI
	private ServerGUI sg;
	// to display time
	private SimpleDateFormat sdf;
	// the port number to listen for connection
	private int port;
	// the boolean that will be turned of to stop the server
	private boolean keepGoing;
        int idSender;
        Cipher c;     
	KeyStore ks;
        X509Certificate cert1Load,cert2Load,cert,cert1,cert2; //dilwsi twn pistopoitikwn pou tha xrisimopiithoun
        Signature sig;
        MessageDigest md;
        final private String KSpass="keystoreSpass";  //kwdikos gia to keystore tou server
        final private String PrKeypass="serverpass";  //kwdikos gia to private key tou server
        final private String TSpass="truststoreSpass";  //kwdikos gia to truststore tou server
        private  PublicKey PubKey1,PubKey2;
        private  PrivateKey PrivKey;
        
	/*
	 *  server constructor that receive the port to listen to for connection as parameter
	 *  in console
	 */
	public Server(int port) {
		this(port, null);
	}
	
	public Server(int port, ServerGUI sg) {
		// GUI or not
		this.sg = sg;
		// the port
		this.port = port;
		// to display hh:mm:ss
		sdf = new SimpleDateFormat("HH:mm:ss");
		// ArrayList for the Client list
		al = new ArrayList<ClientThread>();
	}
	
	public void start() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {
		keepGoing = true;
		/* create socket server and wait for connection requests */
		try 
		{
			// the socket used by the server
			ServerSocket serverSocket = new ServerSocket(port);
                        ks= KeyStore.getInstance("JKS");
                        ks.load(new FileInputStream("C:\\keystoreS.jks"),KSpass.toCharArray());
                         cert = (X509Certificate)ks.getCertificate("Server");  //kanume load to certificate tou server apo to keystore tou
                         PrivKey=(PrivateKey) ks.getKey("Server", PrKeypass.toCharArray());  //pernoume to private key tou server
                         ks.load(new FileInputStream("C:\\truststoreS.jks"),TSpass.toCharArray());
                        cert1Load =(X509Certificate) ks.getCertificate("Client1");  
                        PubKey1=cert1Load.getPublicKey();  //pernoume to public key tou Client1 apo to truststore tou server
                        cert2Load= (X509Certificate)ks.getCertificate("Client2");
                        PubKey2=cert2Load.getPublicKey();  //pernoume to public key tou Client2 apo to truststore tou server
                         
                        
			while(keepGoing) 
			{
				// format message saying we are waiting
				display("Server waiting for Clients on port " + port + ".");
				
				Socket socket = serverSocket.accept();  	// accept connection
				// if I was asked to stop
				if(!keepGoing)
					break;
				ClientThread t = new ClientThread(socket);  // make a thread of it
				al.add(t);				// save it in the ArrayList
				t.start();
			}
			// I was asked to stop
			try {
				serverSocket.close();
				for(int i = 0; i < al.size(); ++i) {
					ClientThread tc = al.get(i);
					try {
					tc.sInput.close();
					tc.sOutput.close();
					tc.socket.close();
					}
					catch(IOException ioE) {
						// not much I can do
					}
				}
			}
			catch(Exception e) {
				display("Exception closing the server and clients: " + e);
			}
		}
		// something went bad
		catch (IOException e) {
            String msg = sdf.format(new Date()) + " Exception on new ServerSocket: " + e + "\n";
			display(msg);
		}
	}		
    /*
     * For the GUI to stop the server
     */
	protected void stop() {
		keepGoing = false;
		// connect to myself as Client to exit statement 
		// Socket socket = serverSocket.accept();
		try {
			new Socket("localhost", port);
		}
		catch(Exception e) {
			// nothing I can really do
		}
	}
	
	private void display(String msg) {
		String time = sdf.format(new Date()) + " " + msg;
		if(sg == null)
			System.out.println(time);
		else
			sg.appendEvent(time + "\n");
	}
	
        
        private synchronized void broadcast(ChatMessage cm,int idSender) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException{
            
            if(cm.getName().equals("Client1")){
             
                cert2Load.checkValidity();
            }
            else{
           
                cert1Load.checkValidity();
            }
           
		for(int i = al.size(); --i >= 0;) {
                        
			ClientThread ct = al.get(i);
                        
                            if(!(ct.id==idSender)){  //apostoli tou minimatos ston client pou perimenei kai oxi se afton pou mas to estile
                               if(!ct.writeMessage(new ChatMessage(1,cm.getBit(),cm.getDig(),cm.getSign(),cm.getUsername(),cm.getName()))) {
				   al.remove(i);
                                   
				   display("Disconnected Client " + ct.username + " removed from list.");
			        }
			
                            }
                            
                        
		}
        }

	// for a client who logoff using the LOGOUT message
	synchronized void remove(int id) {
		// scan the array list until we found the Id
		for(int i = 0; i < al.size(); ++i) {
			ClientThread ct = al.get(i);
			// found it
			if(ct.id == id) {
				al.remove(i);
				return;
			}
		}
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
        
        
	
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException {
		// start server on port 1500 unless a PortNumber is specified 
		int portNumber = 1500;
		switch(args.length) {
			case 1:
				try {
					portNumber = Integer.parseInt(args[0]);
				}
				catch(Exception e) {
					System.out.println("Invalid port number.");
					System.out.println("Usage is: > java Server [portNumber]");
					return;
				}
			case 0:
				break;
			default:
				System.out.println("Usage is: > java Server [portNumber]");
				return;
				
		}
		// create a server object and start it
		Server server = new Server(portNumber);
		server.start();
	}

	/** One instance of this thread will run for each client */
	class ClientThread extends Thread {
		// the socket where to listen/talk
		Socket socket;
		ObjectInputStream sInput;
		ObjectOutputStream sOutput;
		// my unique id (easier for deconnection)
		int id;
		// the Username of the Client
		String username;
		// the only type of message a will receive
		ChatMessage cm,cm1;
		// the date I connect
		String date;
                

		// Constructore
		ClientThread(Socket socket) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
			// a unique id
			id = ++uniqueId;
			this.socket = socket;
			/* Creating both Data Stream */
			System.out.println("Thread trying to create Object Input/Output Streams");
			try
			{
				// create output first
				sOutput = new ObjectOutputStream(socket.getOutputStream());
				sInput  = new ObjectInputStream(socket.getInputStream());
				
                                cm=(ChatMessage) sInput.readObject(); // o server dexete chat message pou periexei to username,name kai pistopiitiko tou client pou sindeetai
                               
                                if(cm.getName().equals("Client1")){ //an sindethike o Client1
                                    cert1=cm.getCert();
                                    cert1Load.verify(cert1.getPublicKey());
                                    
                                }
                                else{ //an sindethike o Client2
                                    cert2=cm.getCert();
                                    cert2Load.verify(cert2.getPublicKey());
                                    
                                   
                                }
				username = cm.getUsername();  //apothikevoume to username
                                
				display(cm.getUsername() + " just connected.");
			}
			catch (IOException e) {
				display("Exception creating new Input/output Streams: " + e);
				return;
			}
			// have to catch ClassNotFoundException
			// but I read a String, I am sure it will work
			catch (ClassNotFoundException e) {
			}
            date = new Date().toString() + "\n";
		}

		// what will run forever
		public void run() {
			// to loop until LOGOUT
			boolean keepGoing = true;
                    try {
                        sOutput.writeObject(cert); //o server stelnei to pistopiitiko tou ston client pou sindethike

                    } catch (IOException ex) {
                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                    }
                        
                        
                        
			while(keepGoing) {
				// read a String (which is an object)
				try {
					cm = (ChatMessage) sInput.readObject();  //diavazei minimata apo client                                      
                              if(cm.getType()==1){ //an ine tipou MESSAGE
                                        idSender=this.id;
                                        byte[] kript = cm.getBit();
                                        sig=Signature.getInstance("SHA256withRSA");
                                        
                                   if (cm.getName().equals("Client1")){ //an o apostoleas ine o Client1
                                       //     cert1Load.verify(cert1.getPublicKey()); //kane verify to public key tou
                                            cert1Load.checkValidity(); //elenxoume an exei liksei to pistopiitiko
                                            sig.initVerify(PubKey1); //elenxoume tin psifiaki ipografi me to public key tou Client1
                                   
                                    }
                                   
                                   else{ //an o apostoleas ine o Client2
                                  //     cert2Load.verify(cert2.getPublicKey()); //kane verify to public key tou
                                       cert2Load.checkValidity(); //elenxoume an exei liksei to pistopiitiko
                                       sig.initVerify(PubKey2); //elenxoume tin psifiaki ipografi me to public key tou Client2
                                          
                                   }       
                                   
                                        //decryption
                                        String msg = decrypt(kript,PrivKey);
                                        
                                        sig.update(msg.getBytes());
                                        sdf = new SimpleDateFormat();
                                        String time = sdf.format(new Date());
                                        String messageLf = time +" "+cm.getUsername()+ ": " + msg + "\n";
                                         //Digest
                                         byte[] sinopsi = Digest(msg);
                                         //checking digest and signature
                                     if((MessageDigest.isEqual(sinopsi,cm.getDig())) && (sig.verify(cm.getSign()))){ //an teriazoun oi dio sinopseis kai oi 2 ipografes
                                         
                                           
               
                                       if(cm.getName().equals("Client1")){ //an o apostoleas ine o Client1
                                                            
                                               
                                              //encrypt
                                              byte[] kript1 = encrypt(msg,PubKey2);
                                              //sign 
                                               byte[] sign1 = DigitalSign(msg,PrivKey);
                                               //create chat message to send
                                               cm1= new ChatMessage(1,kript1,sinopsi,sign1,cm.getUsername(),cm.getName());
                                               
                              
			
                                     }
                                      else{ //an o apostoleas ine o Client2
                                            
                                              //encrypt                                    
                                              byte[] kript1 = encrypt(msg,PubKey1);
                                               //sign
                                               byte[] sign1 = DigitalSign(msg,PrivKey);
                                               //create chat message to send
                                               cm1= new ChatMessage(1,kript1,sinopsi,sign1,cm.getUsername(),cm.getName());
                                               
                                       }
                                     }else{
                                         sg.appendRoom("Digests are not equal or Signature cannot be verified");
                                     }
                                   
                        
		         
                                            
					// if console mode print the message and add back the prompt
					if(sg == null) {
						System.out.print(messageLf);
						System.out.print("> ");
					}
					else {
						sg.appendRoom(messageLf);
                                                //sg.appendRoom("\n");
					}
                                       
                                         
                                }
                                }
                                
				catch (IOException e) {
					display(username + " Exception reading Streams: " + e);
					break;				
				}
				catch(ClassNotFoundException e2) {
					break;
				} catch (InvalidKeyException ex) {
                                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                                sg.appendEvent(" Client failed to authenticate!");
                            } catch (IllegalBlockSizeException ex) {
                                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (BadPaddingException ex) {
                                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (NoSuchAlgorithmException ex) {
                                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (NoSuchPaddingException ex) {
                                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (SignatureException ex) {
                                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                            } catch (CertificateException ex) {
                                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                            }
				//
                            //    String  us = this.username;
                                
				switch(cm.getType()) {

				case ChatMessage.MESSAGE:
                                {
                                    try {
                                        //broadcast(username + ": " + message);
                                        broadcast(cm1,idSender);
                                    } catch (CertificateException ex) {
                                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                                    } catch (NoSuchAlgorithmException ex) {
                                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                                    } catch (InvalidKeyException ex) {
                                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                                    } catch (NoSuchProviderException ex) {
                                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                                    } catch (SignatureException ex) {
                                        Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                                    }
                                }
                               
                           
                                
					break;
				case ChatMessage.LOGOUT:
					display(username + " disconnected with a LOGOUT message.");
					keepGoing = false;
					break;
				case ChatMessage.WHOISIN:
					writeMessage(new ChatMessage(2,"List of the users connected at " + sdf.format(new Date()) + "\n"));
					// scan al the users connected
					for(int i = 0; i < al.size(); ++i) {
						ClientThread ct = al.get(i);
						writeMessage(new ChatMessage(2,(i+1) + ") " + ct.username + " since " + ct.date));
					}
					break;
				}
                                
                                
                                
			}
                        
			// remove myself from the arrayList containing the list of the
			// connected Clients
			remove(id);
			close();
		}
		
		// try to close everything
		private void close() {
			// try to close the connection
			try {
				if(sOutput != null) sOutput.close();
			}
			catch(Exception e) {}
			try {
				if(sInput != null) sInput.close();
			}
			catch(Exception e) {};
			try {
				if(socket != null) socket.close();
			}
			catch (Exception e) {}
		}
		
                
                 public boolean writeMessage(ChatMessage cm){  //sinartisi pou adikathista tin writeMsg. Anti gia String, stelnei minima ChatMessage
                    // if Client is still connected send the message to it
			if(!socket.isConnected()) {
				close();
				return false;
			}
                        try{
                            sOutput.writeObject(cm);
                            
                        }
                        catch(IOException e) {
				display("Error sending message to " + username);
				display(e.toString());
			}
                        return true;
                }
	}
}
