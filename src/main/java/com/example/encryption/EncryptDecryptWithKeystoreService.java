package com.example.encryption;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
@Service
public class EncryptDecryptWithKeystoreService {

    private final KeyStore keyStore;
    @Value("${server.ssl.key-alias}") String alias;
    @Value("${server.ssl.key-store-password}") String keystorePassword;

    public EncryptDecryptWithKeystoreService(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public String encrypt(String plainText) {
        try {

            PublicKey publicKey = getPublicKey(keyStore, alias);
            return encryptWithPublicKey(plainText, publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String decrypt(String encryptedText) {
        try{
            PrivateKey privateKey = getPrivateKey(keyStore, alias, keystorePassword);
            return decryptWithPrivateKey(encryptedText, privateKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private PrivateKey getPrivateKey(KeyStore keystore, String keyAlias, String keyPassword) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Key key = keystore.getKey(keyAlias, keyPassword.toCharArray());
        return (PrivateKey) key;
    }

    private PublicKey getPublicKey(KeyStore keyStore, String keyAlias) throws KeyStoreException {
        Certificate cert = keyStore.getCertificate(keyAlias);
        return cert.getPublicKey();
    }

    private String encryptWithPublicKey(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decryptWithPrivateKey(String encryptedText, PrivateKey privateKey) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedText);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        return new String(decryptedBytes);
    }
}

