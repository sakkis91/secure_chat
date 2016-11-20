/*
 * Source code from http://www.dreamincode.net/forums/topic/259777-a-simple-chat-program-with-clientserver-gui-optional/
 */
import java.io.*;
import java.security.cert.X509Certificate;
/*
 * This class defines the different type of messages that will be exchanged between the
 * Clients and the Server. 
 * When talking from a Java Client to a Java Server a lot easier to pass Java objects, no 
 * need to count bytes or to wait for a line feed at the end of the frame
 */
public class ChatMessage implements Serializable {

	protected static final long serialVersionUID = 1112122200L;

	// The different types of message sent by the Client
	// WHOISIN to receive the list of the users connected
	// MESSAGE an ordinary message
	// LOGOUT to disconnect from the Server
	static final int WHOISIN = 0, MESSAGE = 1, LOGOUT = 2;
	private int type;
	private String message;
        private byte[] bit; //kryptografhma
        private byte[] dig; //sinopsi
        private String name; //name (Client1/Client2)
        private String username;
        private X509Certificate cert; //pistopoihtiko
        private byte[] sign; //upografh
	
	// constructor
	ChatMessage(int type, String message) {//kataskeyasths pou xrhsimopoieitai gia thn leitourgia tou koumpiou WHOISIN
		this.type = type;
		this.message = message;
	}
        
        
        
        
        
        ChatMessage (String username, X509Certificate cert,String name){ //kataskeyasths gia thn antallagh pistopoihtikwn kata thn syndesh enos Client(1 fora)
            this.username=username;
            this.cert=cert;
            this.name=name;
        }
        
        
        
        ChatMessage(int type, byte[] bit, byte[] dig,byte[] sign, String username,String name){//kataskeyasths pou xrhsimopoieitai sthn kanonikh leitourgia antallaghs mhnymatwn
            this.type=type;
            this.bit=bit;
            this.dig=dig;
            this.username=username;
            this.name=name;
            this.sign=sign;
        }
        
       
         
	
	// getters
	int getType() {
		return type;
	}
	String getMessage() {
		return message;
	}
        
        byte[] getBit(){
            return bit;
        }
        
        byte[] getDig(){
            return dig;
        }
        
        String getName(){
            return name;
        }
        
        String getUsername(){
            return username;
        }
        
        X509Certificate getCert(){
            return cert;
        }
        byte[] getSign(){
            return sign;
        }
        
       
}
