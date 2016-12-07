import java.security.*;
import java.security.spec.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.net.*;
import javax.json.*;
import java.util.Random;
import java.util.Scanner;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.CRC32;
import java.nio.ByteBuffer;
import java.io.ByteArrayOutputStream;
import java.util.Scanner;
import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;
import java.lang.Math;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class assignment3 {

	public static void main(String[] args) throws IOException{
        //This code is used to take in the arguments according to their flags.
        String serverURL = "";
        String port = "";
        String username = "";
        String password = "";
        if (args.length >= 6) {
            for (int i = 0; i < args.length / 2; i++) {
                switch(args[2*i]) {
                    case "-s": case "--server":
                        serverURL = args[2*i+1];
                        break;
                    case "-p": case "--port":
                        port = args[2*i+1];
                        break;
                    case "-u": case "--username":
                        username = args[2*i+1];
                        break;
                    case "-w": case "--password":
                        password = args[2*i+1];
                        break;
                    case "-cp":
                        break;
                    default:
                        System.out.println("Invalid input flag:" + args[2*i]);
                        System.exit(0);
                }
            }
        } else {
            System.out.println("Not enough arguments");
        }
        if (serverURL == "") {
            System.out.println("Missing required option: s");
        }    
        if (port == "") {
            System.out.println("Missing required option: p");
        }    
        if (username == "") {
            System.out.println("Missing required option: u");
        }
        try {
            //Register a public key
            KeyPair[] keys = new KeyPair[2];
            keys = registerKeys(serverURL, port, "a");
            
            JsonObject encryptedMessage = getOneMessage(keys, serverURL, port, username);
            while (encryptedMessage == null) {               
                encryptedMessage = getOneMessage(keys, serverURL, port, username);
            }
            System.out.println("Part 1: Message from Alice to Bob");
            System.out.println(encryptedMessage);
            System.out.println("Part 2: Maul the message and keep sending until we encounter a read recipt");
            maul(keys, encryptedMessage, serverURL, port, username, 17);
            String number = getAllMessages(keys, serverURL, port, "a");
            while (number == ""){
                number = getAllMessages(keys, serverURL, port, "a");
            }
            clearAllMessages(keys, serverURL, port, "a");
            System.out.println("Here is the altered message we sent:");
            JsonObject newMessage = recreateMaul(keys, encryptedMessage, serverURL, port, username, number, 17);
            System.out.println(newMessage.toString());
            retroDecrypt(keys, newMessage, serverURL, port, username);
        } catch (Exception e) {
            System.out.println(e + "/nSomething went wrong on line 77");
        }
    }
    
    private static void maul(KeyPair[] keys, JsonObject messageData, String serverURL, String port, String username, int byteNum) {
        Base64.Decoder decoder = Base64.getDecoder();
        Base64.Encoder encoder = Base64.getEncoder();
        
        String encryptedMessage = messageData.getString("message");
        String[] message = encryptedMessage.split(" ");
        
        //Split the message into its parts and decode
        String c1base64 = message[0];
        byte[] c2 = decoder.decode(message[1]);
       
        try {
            for (int i = -128; i < 127 ; i++) { 
                c2[byteNum] = (byte) i;
                                          
                String c2base64String = new String(encoder.encode(c2));
                String combined = c1base64 + " " + c2base64String;
                
                Signature dsaSig = Signature.getInstance("DSA");
                dsaSig.initSign(keys[1].getPrivate());
                dsaSig.update(combined.getBytes());
                byte[] signature = encoder.encode(dsaSig.sign());
                
                //Final ciphertext
                String output = combined + " " + new String(signature);
                
                //Create JsonObject to send to server
                JsonBuilderFactory factory = Json.createBuilderFactory(null);
                String num = String.valueOf(i);
                JsonObject obj = Json.createObjectBuilder().add("recipient", username).add("messageID", num).add("message", output).build();
                String objString = obj.toString();
        
                composeMessage(serverURL, port, "a", username, objString);               
            }   
        } catch (Exception e) {
            System.out.println(e);
        }
    }
    
    private static void retroDecrypt(KeyPair[] keys, JsonObject messageData, String serverURL, String port, String username) {
        Base64.Decoder decoder = Base64.getDecoder();
        String encryptedMessage = messageData.getString("message");
        String[] message = encryptedMessage.split(" ");
        
        byte[] c2 = decoder.decode(message[1]);
        int blocks = (int) Math.ceil(c2.length / 16.0 - 1);
        byte[] cipherPad = new byte[16];
        JsonObject data = messageData;
        for (int i = 1; i <= 16; i ++) {
            try {
            String number = "";
            if (i == 2) {
                Thread.sleep(10000);
                clearAllMessages(keys, serverURL, port, "a");
                System.out.println("hello");
                oneMaul(keys, data, serverURL, port, username, c2.length-i);
                System.out.println("hello");
                while (number == ""){
                    number = getAllMessages(keys, serverURL, port, "a");
                }
                if (number.substring(0, 1) == "1") {
                    cipherPad[16] = (byte)(cipherPad[16] ^ (byte) 1);
                }
                System.out.println("hello");
            } else {
                clearAllMessages(keys, serverURL, port, "a");
                maul(keys, data, serverURL, port, username, c2.length-i);
                number = getAllMessages(keys, serverURL, port, "a");
                while (number == ""){
                    number = getAllMessages(keys, serverURL, port, "a");
                }
            }
            byte val;
            val = (byte)((byte)Integer.parseInt(number) * (byte)i);
            cipherPad[16-i] = val;
            byte value = (byte)((byte)c2[c2.length-i] ^ ((byte)val));
            System.out.println("This plaintext byte value is: " + value);
            for (int j = 1; j <= i; j++) {
                String neededVal = String.valueOf((byte) cipherPad[16-j] ^ ((byte)(i+1))); 
                data = recreateMaul(keys, data, serverURL, port, username, neededVal, c2.length - j);
            }
            } catch (Exception e) {
                System.out.println(e);
            }
        }

        byte[] lastBlock = Arrays.copyOfRange(c2, c2.length - 16, c2.length);
        System.out.println(new String(XorRA(lastBlock, cipherPad, 16)));
       
    }
    
    private static void oneMaul(KeyPair[] keys, JsonObject messageData, String serverURL, String port, String username, int byteNum) {
        Base64.Decoder decoder = Base64.getDecoder();
        Base64.Encoder encoder = Base64.getEncoder();
        
        String encryptedMessage = messageData.getString("message");
        String[] message = encryptedMessage.split(" ");
        
        //Split the message into its parts and decode
        String c1base64 = message[0];
        byte[] c2 = decoder.decode(message[1]);
       
        try {
            for (int j = 0; j < 2; j++) {
                if (j == 1) {
                    c2[byteNum+1] = (byte)(c2[byteNum+1] ^ (byte)1);
                }
                for (int i = -128; i < 127 ; i++) { 
                    c2[byteNum] = (byte) i;
                                              
                    String c2base64String = new String(encoder.encode(c2));
                    String combined = c1base64 + " " + c2base64String;
                    
                    Signature dsaSig = Signature.getInstance("DSA");
                    dsaSig.initSign(keys[1].getPrivate());
                    dsaSig.update(combined.getBytes());
                    byte[] signature = encoder.encode(dsaSig.sign());
                    
                    //Final ciphertext
                    String output = combined + " " + new String(signature);
                    
                    //Create JsonObject to send to server
                    JsonBuilderFactory factory = Json.createBuilderFactory(null);
                    String num = j + String.valueOf(i);
                    JsonObject obj = Json.createObjectBuilder().add("recipient", username).add("messageID", num).add("message", output).build();
                    String objString = obj.toString();
            
                    composeMessage(serverURL, port, "a", username, objString);               
                }   
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    
    private static JsonObject recreateMaul(KeyPair[] keys, JsonObject messageData, String serverURL, String port, String username, String number, int byteNum) {
        Base64.Decoder decoder = Base64.getDecoder();
        Base64.Encoder encoder = Base64.getEncoder();
        
        String encryptedMessage = messageData.getString("message");
        String[] message = encryptedMessage.split(" ");
        
        //Split the message into its parts and decode
        String c1base64 = message[0];
        byte[] c2 = decoder.decode(message[1]);
       
        try { 
            c2[byteNum] = (byte) Integer.parseInt(number);
                                      
            String c2base64String = new String(encoder.encode(c2));
            String combined = c1base64 + " " + c2base64String;
            
            Signature dsaSig = Signature.getInstance("DSA");
            dsaSig.initSign(keys[1].getPrivate());
            dsaSig.update(combined.getBytes());
            byte[] signature = encoder.encode(dsaSig.sign());
            
            //Final ciphertext
            String output = combined + " " + new String(signature);
            
            //Create JsonObject to send to server
            JsonBuilderFactory factory = Json.createBuilderFactory(null);
            String num = String.valueOf(number);
            JsonObject obj = Json.createObjectBuilder().add("recipient", username).add("messageID", num).add("message", output).build();
            return obj;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
   }
    

    private static void composeMessage(String serverURL,String port, String username, String otherUser, String message) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, MalformedURLException {
        //Open the connection to the server
        serverURL = "http://" + serverURL + ":" + port;
        serverURL += "/sendMessage/" + username;
        URL url = new URL(serverURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");

        try( DataOutputStream os = new DataOutputStream(connection.getOutputStream())) {
            os.write(message.getBytes());
        }
        
        connection.getResponseMessage();
    }
    
    private static String encrypt(KeyPair[] keys, String username, String otherUser, String otherKeys, String message) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        Base64.Decoder decoder = Base64.getDecoder();
        Base64.Encoder encoder = Base64.getEncoder();
        //Create rsa publicKey and dsa publicKey Objects from otherKeys string
        String[] otherPublicKeys = otherKeys.split("%");
        byte[] rsaByteKey = decoder.decode(otherPublicKeys[0].getBytes());
        X509EncodedKeySpec rsaX509Key = new X509EncodedKeySpec(rsaByteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey otherRSAPubKey = kf.generatePublic(rsaX509Key);
        
        //Get a key instance of AES size 128
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        
        //Create c1
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/Pkcs1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, otherRSAPubKey);
        byte[] c1 = rsaCipher.doFinal(aesKey.getEncoded());
        
        //Create Mformatted
        String mformatted = username + ":" + message;
        byte[] mformatRA = mformatted.getBytes();
        
        //Create the CRC32 value
        CRC32 crc = new CRC32();
        crc.update(mformatted.getBytes());
        long crcVal = crc.getValue();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(crcVal);
        byte[] crcRA = Arrays.copyOfRange(buffer.array(), 4, 8);
        byte[] mcrc = concat(mformatRA, crcRA);
        
        //Add PKCS5 padding to the message
        byte[] mpadded = concat(mcrc,Pkcs(mcrc));

        //Create a secure random IV
        byte[] IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        
        //Encrypt using AES CTR mode
        Cipher aes = null;
        byte[] c2 = null;
	    try {
	    	aes = Cipher.getInstance("AES/CTR/NoPadding");
	    	aes.init(aes.ENCRYPT_MODE, aesKey, new IvParameterSpec(IV));    
            c2 = aes.doFinal(mpadded);
	    } catch (Exception e){
	    	e.printStackTrace();
	    }
        c2 = concat(IV, c2);
        
        //Get the base64 encoded versions of c1 and c2
        byte[] c1base64 = encoder.encode(c1);
        byte[] c2base64 = encoder.encode(c2);
        String c1base64String = new String(c1base64);
        String c2base64String = new String(c2base64);
        String combined = c1base64String + " " + c2base64String;
        
        Signature dsaSig = Signature.getInstance("DSA");
        dsaSig.initSign(keys[1].getPrivate());
        dsaSig.update(combined.getBytes());
        byte[] signature = encoder.encode(dsaSig.sign());
        
        //Final ciphertext
        String output = combined + " " + new String(signature);
        
        //Create JsonObject to send to server
        JsonBuilderFactory factory = Json.createBuilderFactory(null);
        JsonObject obj = Json.createObjectBuilder().add("recipient", otherUser).add("messageID", "0").add("message", output).build();
        String objString = obj.toString();

        return objString;
    }
   
    /*Function for calculating the appropriate PKCS padding for a message*/
	private static byte[] Pkcs(byte[] messageX) {
		byte[] ps;
		int n = messageX.length % 16;
		ps = new byte[16 - n];
		Arrays.fill(ps, (byte)(16-n));
		return ps;
	}
    
    private static KeyPair[] registerKeys(String serverURL, String port, String username) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, MalformedURLException {
        Base64.Encoder encoder = Base64.getEncoder();
        //Make the rsa key pair and extract the public key
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(1024);
        KeyPair rsa = rsaKeyGen.genKeyPair();
        byte[] rsaPublic = rsa.getPublic().getEncoded();
        String rsaPublicString = new String(encoder.encode(rsaPublic));
        //Make the dsa key pair and extract the public key
        KeyPairGenerator dsaKeyGen = KeyPairGenerator.getInstance("DSA");
        dsaKeyGen.initialize(1024);
        KeyPair dsa = dsaKeyGen.genKeyPair();
        byte[] dsaPublic = dsa.getPublic().getEncoded();
        String dsaPublicString = new String(encoder.encode(dsaPublic));
       
        String keys = rsaPublicString + "%" + dsaPublicString;
        
        //Open the connection to the server
        serverURL = "http://" + serverURL + ":" + port;
        serverURL += "/registerKey/" + username;
        URL url = new URL(serverURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");
        
        //Create a JSON object of our data, then send it
        JsonBuilderFactory factory = Json.createBuilderFactory(null);
        JsonObject obj = Json.createObjectBuilder().add("keyData", keys).build();
        String objString = obj.toString();
        
        try( DataOutputStream os = new DataOutputStream( connection.getOutputStream())) {
            os.write(objString.getBytes());
        }

        connection.getResponseMessage();
        KeyPair[] keyPairs = {rsa, dsa};
        return keyPairs;
    }
    
    private static String getUserKeys(String serverURL, String port, String otherUser) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, MalformedURLException {
        //Open the connection to the server
        serverURL = "http://" + serverURL + ":" + port;
        serverURL += "/lookupKey/" + otherUser.trim();
        URL url = new URL(serverURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");

        BufferedReader input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String keyString;
        
        keyString = input.readLine();
        input.close();
        //Create Json object from the json esque string
        JsonReader reader = Json.createReader(new StringReader(keyString));
        JsonObject userKeys = reader.readObject();
        reader.close();
       
        return userKeys.getString("keyData");
    }
    
    private static JsonObject getOneMessage(KeyPair[] keys, String serverURL, String port, String username) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, MalformedURLException {
        String origURL = serverURL;
        //Open the connection to the server
        serverURL = "http://" + serverURL + ":" + port;
        serverURL += "/getMessages/" + username;
        URL url = new URL(serverURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");

        //Get all the messages
        BufferedReader input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String messages = input.readLine();
        input.close();
        
        //Create Json object from the json esque string
        JsonReader reader = Json.createReader(new StringReader(messages));
        JsonObject allMessages = reader.readObject();
        reader.close();
        
        int numMessages = allMessages.getInt("numMessages");
        JsonArray messageMeta = allMessages.getJsonArray("messages");
        
        if (numMessages > 0) {
            reader = Json.createReader(new StringReader(messageMeta.get(0).toString()));
            JsonObject messageData = reader.readObject();
            return messageData;            
        } else {
            return null;
        }
    }
    
    private static String getAllMessages(KeyPair[] keys, String serverURL, String port, String username) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, MalformedURLException {
        String origURL = serverURL;
        //Open the connection to the server
        serverURL = "http://" + serverURL + ":" + port;
        serverURL += "/getMessages/" + username;
        URL url = new URL(serverURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");

        //Get all the messages
        BufferedReader input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String messages = input.readLine();
        input.close();
        
        //Create Json object from the json esque string
        JsonReader reader = Json.createReader(new StringReader(messages));
        JsonObject allMessages = reader.readObject();
        reader.close();
        
        int numMessages = allMessages.getInt("numMessages");
        JsonArray messageMeta = allMessages.getJsonArray("messages");
        
        for (int i = 0; i < messageMeta.size(); i++) {
            reader = Json.createReader(new StringReader(messageMeta.get(i).toString()));
            JsonObject message = reader.readObject();
            try { 
                String num = decrypt(keys, username, origURL, port, message);
                if (num != "") {
                    return num;
                } 
            } catch (Exception e) {
                System.out.println("Exception while attempting to decrypt message");
                System.out.println(e);
                continue;
            }
        }
        return "";
    }

    private static void clearAllMessages(KeyPair[] keys, String serverURL, String port, String username) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, MalformedURLException {
        String origURL = serverURL;
        //Open the connection to the server
        serverURL = "http://" + serverURL + ":" + port;
        serverURL += "/getMessages/" + username;
        URL url = new URL(serverURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("Accept", "application/json");

        //Get all the messages
        BufferedReader input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String messages = input.readLine();
        input.close();
        
        //Create Json object from the json esque string
        JsonReader reader = Json.createReader(new StringReader(messages));
        JsonObject allMessages = reader.readObject();
        reader.close();
        
        int numMessages = allMessages.getInt("numMessages");
        JsonArray messageMeta = allMessages.getJsonArray("messages");
    }

    private static String decrypt(KeyPair[] keys, String username, String serverURL, String port, JsonObject messageData) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, ProtocolException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException {
        Base64.Decoder decoder = Base64.getDecoder();
        //Get all thed aata from the messageData
        int time = messageData.getInt("sentTime");
        String senderID = messageData.getString("senderID");
        int messageID = messageData.getInt("messageID");
        String encryptedMessage = messageData.getString("message");
        String[] message = encryptedMessage.split(" ");
        
        
        //Split the message into its parts and decode
        String c1Base64 = message[0];
        String c2Base64 = message[1];
        byte[] c1 = decoder.decode(message[0].getBytes());
        byte[] c2 = decoder.decode(message[1]);
        byte[] sigma = decoder.decode(message[2].getBytes());
        
        String otherKeyString = getUserKeys(serverURL, port, senderID);
        String[] otherKeys = otherKeyString.split("%");
              
        //Verify dsa signature
        byte[] dsaByteKey = decoder.decode(otherKeys[1].getBytes());
        X509EncodedKeySpec dsaX509Key = new X509EncodedKeySpec(dsaByteKey);
        KeyFactory kf = KeyFactory.getInstance("DSA");
        PublicKey otherDSAPubKey = kf.generatePublic(dsaX509Key);
        
        //Verify the signature
        Signature dsaSig = Signature.getInstance("DSA");
        dsaSig.initVerify(otherDSAPubKey);
        dsaSig.update((c1Base64 + " " + c2Base64).getBytes());
        boolean verified = dsaSig.verify(sigma);
        if (!verified) {
            return "";
        }
        
        //Find K
        byte[] K = null;
        try {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/Pkcs1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, keys[0].getPrivate());
            K = rsaCipher.doFinal(c1);
        }catch (Exception e) {
            return "";
        }
        SecretKey aesKey = new SecretKeySpec(K, 0, K.length, "AES"); 
        
        //Find the Mpadded
        byte[] mpadded = null;
        try {
            byte[] IV = Arrays.copyOfRange(c2, 0, 16);
    	    Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
        	aes.init(aes.DECRYPT_MODE, aesKey, new IvParameterSpec(IV));    
            mpadded = aes.doFinal(Arrays.copyOfRange(c2, 16, c2.length));
        }catch (Exception e) {
            System.out.println(e);
            return "";
        }
        //Verify the pkcs padding
        byte endByte = mpadded[mpadded.length - 1];
        for (int i = 1; i < (int)endByte + 1; i++) {
            if (mpadded[mpadded.length - i] != endByte) {
                return "";
            }
        }
        //Compute mcrc and verify the crc
        byte[] mcrc = Arrays.copyOfRange(mpadded, 0, mpadded.length - (int)endByte);
        byte[] mformatted = Arrays.copyOfRange(mcrc, 0, mcrc.length - 4);
        byte[] crc = Arrays.copyOfRange(mcrc, mcrc.length - 4, mcrc.length);
        CRC32 verifyCrc = new CRC32();
        verifyCrc.update(mformatted);
        long crcVal = verifyCrc.getValue();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(crcVal);
        byte[] crcRA = Arrays.copyOfRange(buffer.array(), 4, 8);
        
        for (int i = 0; i < 4; i++) {
            if (crcRA[i] != crc[i]) {
                return "";
            }
        }
        
        //Parse Mformatted as user message
        String mformmatedString = new String(mformatted);
        String[] messageParts = mformmatedString.split(":");
        if (!messageParts[0].equals(senderID)) {
            return "";
        }
        
        String num = mformmatedString.substring(messageParts[0].length() + 1, mformmatedString.length()).split(" ")[1];
        System.out.println("Message ID: " + messageID);
        System.out.println("From: " + senderID);
        System.out.println(mformmatedString.substring(messageParts[0].length() + 1, mformmatedString.length()));
        return num;
    }
    
    //Function for XORing a byte array
	private static byte[] XorRA(byte[] a, byte[] b, int length) {
		byte[] ra = new byte[length];
		for (int i = 0; i < length; i++) {
			ra[i] = (byte)((int)a[i] ^ (int)b[i]);
		}
		return ra;
	}
	
    //Function for concatenating two byte arrays
	private static byte[] concat(byte[] a, byte[] b) {
		int total = a.length + b.length;
		byte[] c = new byte[total];
		for (int i = 0; i < total; i++) {
			if (i < a.length) {
				c[i] = a[i];
			} else {
				c[i] = b[i- a.length];
			}
		}
		return c;
	}
}
