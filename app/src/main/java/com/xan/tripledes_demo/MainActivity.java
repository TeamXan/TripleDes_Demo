package com.xan.tripledes_demo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {
    public static String ALGO = "DESede/ECB/PKCS7Padding";
    String encryptedString;
    String plainString;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
           // encryptedString = encrypt("Ei","Ei@123");
            plainString =  _decrypt(encrypt("Ei","Ei@123"),"Ei@123");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    public static String encrypt(String message, String secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance(ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, getSecreteKey(secretKey));

        byte[] plainTextBytes = message.getBytes("UTF-8");
        byte[] buf = cipher.doFinal(plainTextBytes);
        byte[] base64Bytes = Base64.encode(buf, Base64.DEFAULT);
        String base64EncryptedString = new String(base64Bytes);
        return base64EncryptedString;
    }

    public static String _decrypt(String encryptedText, String secretKey) throws Exception {

        byte[] message = Base64.decode(encryptedText.getBytes("UTF-8"), Base64.DEFAULT);

        Cipher decipher = Cipher.getInstance(ALGO);
        decipher.init(Cipher.DECRYPT_MODE, getSecreteKey(secretKey));

        byte[] plainText = decipher.doFinal(message);
        String base64DecryptedString = new String(plainText);
       // return new String(plainText, "UTF-8");
        return base64DecryptedString;
    }

    public static SecretKey getSecreteKey(String secretKey) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digestOfPassword = md.digest(secretKey.getBytes("utf-8"));
        byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        return key;
    }
}
