package com.example.encryption;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@SpringBootApplication
public class EncryptionApplication {

	public static void main(String[] args) {
		SpringApplication.run(EncryptionApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(EncryptDecryptWithKeystoreService encryptDecryptWithKeystoreService){
		return (args) ->{
			System.out.println("acs");
			String plainText = "Hello, world!";
			String encString = encryptDecryptWithKeystoreService.encrypt(plainText);

			// Decrypt the text
			String decryptedText = encryptDecryptWithKeystoreService.decrypt(encString);
			System.out.println("Decrypted text: " + decryptedText);
		};
	}

	@Bean
	public KeyStore keyStore(@Value("${server.ssl.key-store}") String keystoreFile, @Value("${server.ssl.key-store-password}") String keystorePassword){
		try(FileInputStream fis = new FileInputStream(keystoreFile)) {
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(fis, keystorePassword.toCharArray());
			return keystore;
		} catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
