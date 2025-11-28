package com.ideas2it.aes256;

import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

//temp nabil//
import shaded.org.apache.commons.codec.binary.Hex;

/**
 * This class used to perform AES encryption and decryption.
 */
public class AES256 extends CordovaPlugin {

    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";
    private static final String GENERATE_SECURE_KEY = "generateSecureKey";
    private static final String GENERATE_SECURE_IV = "generateSecureIV";

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final int PBKDF2_ITERATION_COUNT = 1001;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SECURE_IV_LENGTH = 64;
    private static final int SECURE_KEY_LENGTH = 128;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String PBKDF2_SALT = "hY0wTq6xwc6ni01G";
    private static final Random RANDOM = new SecureRandom();

    
  //temp nabil//private static final String SYMMETRIC_ENCRYPTION = "AES/CBC/PKCS7Padding";
    public static final String UTF8 = "UTF-8";
    public static final String AES = "AES";
    
    @Override
    public boolean execute(final String action, final JSONArray args,  final CallbackContext callbackContext) throws JSONException {
        try {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        if (ENCRYPT.equalsIgnoreCase(action)) {
                            String secureKey = args.getString(0);
                            String iv = args.getString(1);
                            String value = args.getString(2);
                            callbackContext.success(encrypt(secureKey, value, iv));
                        } else if (DECRYPT.equalsIgnoreCase(action)) {
                            String secureKey = args.getString(0);
                            String iv = args.getString(1);
                            String value = args.getString(2);
                            callbackContext.success(decrypt(secureKey, value, iv));
                        } else if (GENERATE_SECURE_KEY.equalsIgnoreCase(action)) {
                            String password = args.getString(0);
                            callbackContext.success(generateSecureKey(password));
                        } else if (GENERATE_SECURE_IV.equalsIgnoreCase(action)) {
                            String password = args.getString(0);
                            callbackContext.success(generateSecureIV(password));
                        } else {
                            callbackContext.error("Invalid method call");
                        }
                    } catch (Exception e) {
                        System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
                        callbackContext.error("Error occurred while performing " + action);
                    }
                }
            });
        } catch (Exception e) {
            System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
            callbackContext.error("Error occurred while performing " + action);
        }
        return  true;
    }

    public static String encrypt(String secureKey, String value, String iv) throws Exception
    {
	//issue #1231427 appeared during stress testing : commenting addProvider and moving it to the static block at the beginning of this class to avoid blocking threads
	//Security.addProvider(new BouncyCastleProvider());
	SecretKey secretKey = new SecretKeySpec(secureKey.getBytes(), AES);
	
	Cipher c = Cipher.getInstance(CIPHER_TRANSFORMATION  /*SYMMETRIC_ENCRYPTION*/);
	byte[] ivByte = iv.getBytes();
	IvParameterSpec initialisationVector = new IvParameterSpec(ivByte);
	c.init(Cipher.ENCRYPT_MODE, secretKey, initialisationVector);
	byte[] encVal = c.doFinal(value.getBytes(UTF8));
	java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
	return new String(encoder.encode(encVal), UTF8);
    }

    
    
    public static String decrypt(String secureKey, String value, String iv) throws Exception
    {
	//issue #1231427 appeared during stress testing : commenting addProvider and moving it to the static block at the beginning of this class to avoid blocking threads
	//Security.addProvider(new BouncyCastleProvider());
	SecretKey secretKey = new SecretKeySpec(secureKey.getBytes(), AES);
	
	java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
	byte[] ivByte = iv.getBytes();
	IvParameterSpec initialisationVector = new IvParameterSpec(ivByte);
	Cipher c = Cipher.getInstance(CIPHER_TRANSFORMATION /*SYMMETRIC_ENCRYPTION*/ );
	c.init(Cipher.DECRYPT_MODE, secretKey, initialisationVector);
	byte[] decValue = c.doFinal(decoder.decode(value));
	return new String(decValue, UTF8);
    }

    /**
     * @param password       The password
     * @param salt           The salt
     * @param iterationCount The iteration count
     * @param keyLength      The length of the derived key.
     * @return PBKDF2 secured key
     * @throws Exception
     * @see <a href="https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html">
     * https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec.html</a>
     */
    private static byte[] generatePBKDF2(char[] password, byte[] salt, int iterationCount,
                                         int keyLength) throws Exception {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        KeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey.getEncoded();
    }

    /**
     * <p>
     * This method used to generate the secure key based on the PBKDF2 algorithm
     * </p>
     *
     * @param password The password
     * @return SecureKey
     * @throws Exception
     */
    private static String generateSecureKey(String password) throws Exception {
        byte[] secureKeyInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(),
                PBKDF2_ITERATION_COUNT, SECURE_KEY_LENGTH);
        return Hex.encodeHexString(secureKeyInBytes);
        //temp nabil//return null;
    }

    /**
     * <p>
     * This method used to generate the secure IV based on the PBKDF2 algorithm
     * </p>
     *
     * @param password The password
     * @return SecureIV
     * @throws Exception
     */
    private static String generateSecureIV(String password) throws Exception {
        byte[] secureIVInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(),
                PBKDF2_ITERATION_COUNT, SECURE_IV_LENGTH);
        return Hex.encodeHexString(secureIVInBytes);
      //temp nabil//return null;
    }

    /**
     * <p>
     * This method used to generate the random salt
     * </p>
     *
     * @return
     */
    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }
}
