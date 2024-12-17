package montest;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.asn1.ASN1Encodable;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.io.ByteArrayInputStream;

public class firefoxLaunch {
	
	static {
        Security.addProvider(new BouncyCastleProvider());
    }
	
	 // Chemin du dossier de profil Firefox (à adapter selon votre système)
    private static String key4DbPath = null;
   private static String loginsJsonPath = null;

   private static final String FIREFOX_PROFILE_PATH = System.getProperty("user.home") 
           + "/AppData/Roaming/Mozilla/Firefox/Profiles";

   private  String PRIMARY_PASSWORD = "";
   private static  byte[] item1 = null; // Retrieve from key4.db
   private static  byte[] item2 = null; // Retrieve from key4.db
   protected  ArrayList<DecryptedData> listeDonnée=new ArrayList<DecryptedData>();
  
    public firefoxLaunch() {
	
}


	public  void firefoxDecryptData() {   
    	//get the path to key4.db and logins json files
    	 Pathretreive();
    if(key4DbPath != null && loginsJsonPath != null) {
     // Retrieve item1 and item2 from key4.db
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:"+ key4DbPath)) {
            String query = "SELECT item1, item2 FROM metadata WHERE id = 'password'";
            try (PreparedStatement pstmt = conn.prepareStatement(query);
                 ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    item1 = rs.getBytes("item1");
                    item2 = rs.getBytes("item2");
                }
            }    
         } catch (SQLException e) {
				e.printStackTrace();
        }
        //verification of the correctness of the key decryption algorithm
        try {
			byte[]passwrdchek=decodeItem2(item2,item1);
			if(passwordCheck(passwrdchek)) {
				byte[] a11= lecture() ;
				byte[]decryptkey1=decodeItem2(a11,item1);
				firefoxLoginReader( loginsJsonPath,decryptkey1);
			}
        
        } catch (Exception e) {
            e.printStackTrace();
        	}
     }
    }

   
    /**
     * Decodes item2 to extract entry salt and encrypted password-check.
     */
    @SuppressWarnings("resource")
    public static byte[] decrypteData(byte[] encodedData,byte[] key) {
    	byte []decrypteddata=null;
    	//ASN1 der decoding
    	ASN1InputStream asn1InputStream = new ASN1InputStream(encodedData);
    	ASN1Primitive asn1Primitive;
		try {
			asn1Primitive = asn1InputStream.readObject();
		
    	ASN1Sequence sequence = (ASN1Sequence) asn1Primitive;
    	// Element 0 
    	/*ASN1OctetString element0 = (ASN1OctetString) sequence.getObjectAt(0); 
    	//byte[] keyId= element0.getOctets();// to check if the data match a12 of key4.db
    	 */
    	// Element 1  the iv 8 bytes
    	ASN1Sequence element1 = (ASN1Sequence) sequence.getObjectAt(1);
    	//ASN1ObjectIdentifier nestedElement0 = (ASN1ObjectIdentifier) element1.getObjectAt(0); //give information about the decrypting algorithm
    	ASN1OctetString nestedElement1 = (ASN1OctetString) element1.getObjectAt(1); 
    	byte[] iv=nestedElement1.getOctets();
    	// Element 2 encrypted data
    	ASN1OctetString element2 = (ASN1OctetString) sequence.getObjectAt(2); 
    	byte[] encrypteddata=element2.getOctets();
    	//decrypte 3des
    	decrypteddata=Decrypt3Des(encrypteddata,key,iv);
    	//fin 
    } catch (IOException e) {
		e.printStackTrace();
	}
    	return decrypteddata;
    }
	@SuppressWarnings("resource")
	public  byte[] decodeItem2(byte[] item2Data,byte[] globalsalt) throws Exception {
    	//decrypted value   
    	byte[] decryptedData=null;
    	// Parse item2 with ASN1InputStream
        ASN1InputStream asn1InputStream = new ASN1InputStream(item2Data);
        ASN1Primitive topLevel = asn1InputStream.readObject();
        if (topLevel instanceof ASN1Sequence) {
            ASN1Sequence sequence = (ASN1Sequence) topLevel;
            // Navigate to get the the iv
            ASN1Sequence nestedSequence1 = (ASN1Sequence) sequence.getObjectAt(0);
            ASN1Sequence nestedSequence2 = (ASN1Sequence) nestedSequence1.getObjectAt(1);
            ASN1Sequence nestedSequence3 = (ASN1Sequence) nestedSequence2.getObjectAt(1); 
            ASN1OctetString ivOctetString = (ASN1OctetString) nestedSequence3.getObjectAt(1);
            byte[] iv1= ivOctetString.getOctets();
            //completing the iv
            byte[] iv = new byte[16];
            iv[0] = 0x04;
            iv[1] = 0x0E;
            System.arraycopy(iv1, 0, iv, 2, iv1.length);
        //encrypted password_chek
            ASN1OctetString encryptedPasswordCheckObj= (ASN1OctetString) sequence.getObjectAt(1);
            byte[]  encryptedPasswordCheck = encryptedPasswordCheckObj.getOctets();
            //entry salt 
            ASN1Sequence innerSequence1 = (ASN1Sequence) sequence.getObjectAt(0);
            ASN1Sequence saltSeq1 = (ASN1Sequence) ((ASN1Sequence) innerSequence1.getObjectAt(1)).getObjectAt(0);
            ASN1OctetString entrySaltObj1 = (ASN1OctetString)( (ASN1Sequence)saltSeq1.getObjectAt(1)).getObjectAt(0);
            byte[] entrySalt= entrySaltObj1.getOctets();
            //get the derived key
            byte[] derivedKey = deriveKey(item1,entrySalt, PRIMARY_PASSWORD);
            //decrypt the data using aes256 
           decryptedData = decryptKey(derivedKey, iv, encryptedPasswordCheck); 
            //end 
        } else {
            throw new IllegalArgumentException("Expected ASN1Sequence but found " + topLevel.getClass().getName());
        }

        asn1InputStream.close();
        //return decrypted data
        return decryptedData;
    }
    /**
     * recherche du chemin menant au Key4db et logins.json for data 
     * affiche les chemins des fichiers rechechés.
     */
        private static void Pathretreive() {
     	 File profileDir = new File(FIREFOX_PROFILE_PATH);
         List<File> foundFiles = new ArrayList<>();
         if (profileDir.exists() && profileDir.isDirectory()) {
             scanDirectory(profileDir, foundFiles);
             if (key4DbPath != null && loginsJsonPath != null) {
                 System.out.println("Chemins trouvés !");
             } else {
                 System.out.println("Les fichiers key4.db et/ou logins.json sont introuvables dans le dossier de profil.");
             }
         } else {
             System.out.println("Le dossier de profil spécifié n'existe pas ou n'est pas un répertoire.");
         }
     }
        
        /**
         * Parcourt récursivement un répertoire à la recherche de key4.db et logins.json.
         * Arrête la recherche dès que les deux fichiers sont trouvés.
         *
         * @param directory Répertoire à scanner
         * @param foundFiles Liste des fichiers trouvés (se limite à key4.db et logins.json)
         */
        private static void scanDirectory(File directory, List<File> foundFiles) {
            File[] files = directory.listFiles();

            if (files != null) {
                for (File file : files) {
                    // Vérifie si les fichiers key4.db ou logins.json sont trouvés
                    if (file.isFile()) {
                        if (file.getName().equals("key4.db")) {
                            key4DbPath = file.getAbsolutePath();
                            foundFiles.add(file);
                        } else if (file.getName().equals("logins.json")) {
                            loginsJsonPath = file.getAbsolutePath();
                            foundFiles.add(file);
                        }
                    } else if (file.isDirectory()) {
                        // Parcours récursif des sous-dossiers
                        scanDirectory(file, foundFiles);
                    }

                    // Arrête la recherche si les deux fichiers ont été trouvés
                    if (key4DbPath != null && loginsJsonPath != null) {
                        return;
                    }
                }
            }
          
        }
      	
        /**
         * Debug methode (utility)
         * Inspect the Asn1 DER structure 
         * @param item2
         */
        public static void inspectSequence1(byte[] item2) {
            System.out.println("Raw item2 data (hex): " + new String(item2));
            try  {
            	ASN1Primitive obj = ASN1Primitive.fromByteArray(item2);
                if (obj instanceof ASN1Sequence) {
                    ASN1Sequence sequence = (ASN1Sequence) obj;
                    System.out.println("Sequence contains " + sequence.size() + " elements.");
                } else {
                    System.out.println("The object is not an ASN1Sequence as expected.");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        /**
         * walk through the asn1 structure.
         * @param encodedData
         * @throws IOException
         */
        public static void inspectSequence(byte[] encodedData) throws IOException {
            // Use ASN1InputStream to read the encoded data
            ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(encodedData));
            ASN1Primitive obj = asn1InputStream.readObject();

            if (obj instanceof ASN1Sequence) {
                ASN1Sequence sequence = (ASN1Sequence) obj;
                System.out.println("Top-level sequence contains " + sequence.size() + " elements:");

                // Iterate through each item in the sequence
                for (int i = 0; i < sequence.size(); i++) {
                    ASN1Encodable element = sequence.getObjectAt(i);
                    printASN1Object(element, "Element " + i);
                }
            } else {
                System.out.println("Not a sequence: " + obj.getClass().getSimpleName());
            }

            asn1InputStream.close();
        }

        private static void printASN1Object(ASN1Encodable obj, String label) {
            System.out.print(label + ": ");
            if (obj instanceof ASN1OctetString) {
                ASN1OctetString octetString = (ASN1OctetString) obj;
                
                System.out.println("ASN1OctetString - Value: " +  bytesToHex(octetString.getOctets()));
            } else if (obj instanceof ASN1Integer) {
                ASN1Integer integer = (ASN1Integer) obj;
                System.out.println("ASN1Integer - Value: " + integer.getValue());
            } else if (obj instanceof ASN1Sequence) {
                System.out.println("ASN1Sequence - Contains " + ((ASN1Sequence) obj).size() + " elements");
                ASN1Sequence sequence = (ASN1Sequence) obj;
                for (int i = 0; i < sequence.size(); i++) {
                    printASN1Object(sequence.getObjectAt(i), label + " - Nested Element " + i);
                }
            } else if (obj instanceof ASN1ObjectIdentifier) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) obj;
                System.out.println("ASN1ObjectIdentifier - Value: " + oid.getId());
            } else {
                System.out.println(obj.getClass().getSimpleName() + " - Unable to parse specific type");
            }
        }
// end utilities for debug
       //test lecture
        
        /**
         * get the A11 from key4.db which contain the encrypted key.
         * @return Byte[] a11
         */
        public static byte[] lecture() {
        	 String dbPath = key4DbPath; // Replace with actual path
        	 byte[] a11 =null;
 	        // JDBC URL for SQLite
 	        String jdbcUrl = "jdbc:sqlite:" + dbPath;
 	        try (Connection conn = DriverManager.getConnection(jdbcUrl)) {
 	            if (conn != null) {
 	                System.out.println("Connected to key4.db successfully!");
 	                // Query to list table schema
 	                String tableQuery = "SELECT a11,a102 FROM nssPrivate";
 	                try (Statement stmt = conn.createStatement();
 	                     ResultSet rs = stmt.executeQuery(tableQuery)) {
 	                    while (rs.next()) {
 	                    	a11 = rs.getBytes("a11");
 	                    	//byte []a102 = rs.getBytes("a102");//you can use it to verify if the encrypted data are related to the key by checking its value 
 	                       }
 	                }
 	            }
 	        } catch (Exception e) {
 	            e.printStackTrace();
 	        }
 	    return a11;
        }
        //end

        
       
        //passwordcheck
        /**
         * check if the the decrypted pasword check is what we were waiting meaning that the  
         * key decryption code is working.
         * @param passwordCheck
         * @return boolean 
         */
        private static boolean passwordCheck(byte[] passwordCheck) {
            byte[] checkValue = "password-check".getBytes();
            return Arrays.equals(passwordCheck, checkValue);
        }
        //end
        
        //pad iv
        public static byte[] padIV(byte[] iv) { 
        	if (iv.length == 14) { 
        		byte[] paddedIv = new byte[16]; 
        		
        		System.arraycopy(iv, 0, paddedIv, 0, iv.length); 
        		return paddedIv; }
        	return iv; }  
        public static String bytesToHex1(byte[] bytes) { StringBuilder sb = new StringBuilder(); for (byte b : bytes) { sb.append(String.format("%02x", b)); } return sb.toString(); }

///last test 
        /**
         * 
         * @param globalSalt:byte[]
         * @param entrySalt:byte[]
         * @param masterPassword: String
         * @return key; byte[]
         * @throws Exception
         */
        public static byte[] deriveKey(byte[] globalSalt, byte[] entrySalt, String masterPassword) throws Exception {
        	   int iterationCount = 1; // Number of iterations
        	    int keyLength = 256; // Desired key length in bytes

        	    // Step 1: Compute SHA-1(globalSalt + masterPassword)
        	    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        	    //digested key after hashing
        	    byte[] intermediateKey = sha1.digest(concatenate(globalSalt, masterPassword.getBytes()));
        	    // Step 2: Derive the key using PBKDF2-HMAC-SHA256 using bounty castle
        	    PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest()); //bountycastle method to get the key using the intermediate key in byte instead of char[](not good in java)
        	    gen.init(intermediateKey, entrySalt, iterationCount);
        	    byte[] key = ((KeyParameter) gen.generateDerivedParameters(keyLength)).getKey();
        	   // System.out.println("Derived key: " + bytesToHex(key));// just for debug needs
        	    return key;
        	//end
        	} 
        /**
         * aes 256 decryption algorithm
         * @param derivedKey :byte[]
         * @param iv:byte[]
         * @param cipherText:byte[]
         * @return decrypteddata:byte[]
         * @throws Exception
         */
        public static byte[] decryptKey(byte[] derivedKey, byte[] iv, byte[] cipherText) throws Exception { 
        	  // Initialize the cipher
        	try {
        	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Use PKCS5Padding for better compatibility
        	    SecretKeySpec secretKey = new SecretKeySpec(derivedKey, "AES");
        	    IvParameterSpec ivSpec = new IvParameterSpec(iv);

        	    // Initialize the cipher for decryption
        	    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        	    // Decrypt the ciphertext
        	    byte[] plaintextBytes = cipher.doFinal(cipherText);
        	    return plaintextBytes; // Or return plaintext if working with a string is preferable
        	} catch (Exception e) {
        	    // Handle exceptions properly
        	    System.err.println("Decryption failed: " + e.getMessage());
        	    e.printStackTrace();
        	    return null;
        	}
        	}
        
        //TripledesDecrypt for logins 
        /**
         * Decrypt the longins json data using 3des cbc with PKCS5Padding 
         * @param encrypteddata :[] byte
         * @param key:[] byte
         * @param iv:[] byte
         * @return decrypteddata:[] byte
         */
        
   public static  byte[] Decrypt3Des(byte[]encrypteddata,byte[] key,byte[] iv) {
        	byte[] decryptedBytes=null;
        	SecretKeySpec secretKey = new SecretKeySpec(key,"DESede");
    	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
        	 // Decrypt the message
            Cipher decryptCipher;
			try {
				decryptCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            decryptedBytes = decryptCipher.doFinal(encrypteddata);
            
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
			return decryptedBytes;
        }
        // Utility function to concatenate two byte arrays
        private static byte[] concatenate(byte[] a, byte[] b) {
            byte[] result = new byte[a.length + b.length];
            System.arraycopy(a, 0, result, 0, a.length);
            System.arraycopy(b, 0, result, a.length, b.length);
            return result;
            
        }
        
        // Utility function to convert a byte array to a hex string
        private static String bytesToHex(byte[] bytes) {
        	StringBuilder sb = new StringBuilder(); 
        	for (byte b : bytes) { 
        		sb.append(String.format("%02x", b)); 
        		} return sb.toString();
        		
        }

        //read login file and decrypt them.
        public  void firefoxLoginReader(String path,byte[] key) {
          // Construire le chemin complet du fichier logins.json
          String loginsJsonPath = path;
          try {
              // Lire le contenu de logins.json
              String content = new String(Files.readAllBytes(Paths.get(loginsJsonPath)));
              // Analyser le contenu JSON
              JSONObject json = new JSONObject(content);
              JSONArray loginsArray = json.getJSONArray("logins");
              // Afficher les identifiants (chiffrés)
              for (int i = 0; i < loginsArray.length(); i++) {
                  JSONObject login = loginsArray.getJSONObject(i);
                  String hostname = login.getString("hostname");
                  String encryptedUsername = login.getString("encryptedUsername");
                  String encryptedPassword = login.getString("encryptedPassword");
                  System.out.println("Nom du site : " +hostname);
                  //step 2 base 64 decoding of username ,its asn1 der decoding followed by ist 3des decryption.
                  byte[] encryptednameBytes = Base64.getDecoder().decode( encryptedUsername);
                  byte[] decryptednameBytes  = decrypteData(encryptednameBytes, key);//asn1 der decryption and 3des cbc decoding.
                  String username= new String(decryptednameBytes);
                  System.out.println("Nom d'utilisateur (dechiffré) : " + username);
                  //step 3 base 64 decoding of pasword ,its asn1 der decoding followed by ist 3des decryption.
                  byte[] encryptedpasswordBytes = Base64.getDecoder().decode(encryptedPassword);
                  byte[] decryptedpasswordBytes= decrypteData(encryptedpasswordBytes, key);
                  String password= new String(decryptedpasswordBytes);
                  System.out.println("Mot de passe (déchiffré) : " + new String(decryptedpasswordBytes));
                  System.out.println("---------------");
                  //stockage des données
                  DecryptedData data= new DecryptedData(hostname, username,password);
                  listeDonnée.add(data);
              }
             
          } catch (IOException e) {
              System.err.println("Erreur lors de la lecture du fichier logins.json : " + e.getMessage());
          } catch (JSONException e) {
              System.err.println("Erreur lors de l'analyse JSON : " + e.getMessage());
          }
  		
  	}
        //end


		public String getPRIMARY_PASSWORD() {
			return PRIMARY_PASSWORD;
		}


		public void setPRIMARY_PASSWORD(String pRIMARY_PASSWORD) {
			PRIMARY_PASSWORD = pRIMARY_PASSWORD;
		}


		public ArrayList<DecryptedData> getListeDonnee() {
			return listeDonnée;
		}
}