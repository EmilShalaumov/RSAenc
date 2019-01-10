package com.ES;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, SignatureException {
        //Cipher cipher = Cipher.getInstance("RSA");
        String publicKeyFileName = "publicKey";
        String privateKeyFileName = "privateKey";

        if(EDC.createKeyFiles(publicKeyFileName, privateKeyFileName))
            System.out.println("Key pair is successfully generated.");

        /*Cipher cipher = Cipher.getInstance(EDC.encodingAlgorithm);
        String origString = "Hello everybody!!! Всем привет@";

        Key decodedPublic = EDC.getPublicKey(publicKeyFileName);
        if (decodedPublic != null) {
            System.out.println("Decoded public from file: " + decodedPublic.toString());
            cipher.init(Cipher.ENCRYPT_MODE, decodedPublic);
            byte[] bytes = cipher.doFinal(origString.getBytes());
            for (byte b : bytes) {
                System.out.println(b);
            }
            System.out.println("\n");

            Key decodedPrivate = EDC.getPrivateKey(privateKeyFileName);
            if (decodedPrivate != null) {
                System.out.println("Decoded private from file: " + decodedPrivate.toString() + "\n");
                cipher.init(Cipher.DECRYPT_MODE, decodedPrivate);
                byte[] decryptedBytes = cipher.doFinal(bytes);
                System.out.println(new String(decryptedBytes));
            }
        }*/

        //String encodedFileName = EDC.encodeFile("in.txt", publicKeyFileName);
        //System.out.println(encodedFileName);

        //System.out.println(EDC.decodeArray(encodedFileName, privateKeyFileName));

        String strToSign = "Is this the real life? Is this just fantasy?";
        String strToCheck = "It is not real life. It's just a fantasy.";

        System.out.println("Source string: \"" + strToSign +"\"\n");

        String signature = EDC.signString(strToSign, privateKeyFileName);
        System.out.println("String is signed. Signature was put to file with name " + signature + ".\n");

        System.out.println("Checking signature with the same string: " + strToSign);
        if (EDC.checkSignature(strToSign, signature, publicKeyFileName))
            System.out.println("Signature test is passed.");
        else
            System.out.println("Signature test is failed.");
        System.out.println();

        System.out.println("Checking signature with the other string: " + strToCheck);
        if (EDC.checkSignature(strToCheck, signature, publicKeyFileName))
            System.out.println("Signature test is passed.");
        else
            System.out.println("Signature test is failed.");

    }
}
