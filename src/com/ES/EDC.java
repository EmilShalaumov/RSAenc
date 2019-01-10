package com.ES;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

class EDC {

    static final String encodingAlgorithm = "RSA";
    private static final int chunkSizeToEncrypt = 245;

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator pairGen = KeyPairGenerator.getInstance(encodingAlgorithm);
        return pairGen.generateKeyPair();
    }

    static boolean createKeyFiles(String publicKeyFileName, String privateKeyFileName) throws NoSuchAlgorithmException, IOException {
        KeyPair keyPair = generateKeyPair();
        Key publicKey = keyPair.getPublic();
        Key privateKey = keyPair.getPrivate();

        FileOutputStream keyFosPublic = new FileOutputStream(publicKeyFileName);
        keyFosPublic.write(publicKey.getEncoded());
        keyFosPublic.close();

        FileOutputStream keyFosPrivate = new FileOutputStream(privateKeyFileName);
        keyFosPrivate.write(privateKey.getEncoded());
        keyFosPrivate.close();

        return true;
    }

    static Key getPublicKey(String FileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream keyFIS = new FileInputStream(FileName);
        byte[] encKey = new byte[keyFIS.available()];
        if (keyFIS.read(encKey) != -1) {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encKey);
            KeyFactory kf = KeyFactory.getInstance(encodingAlgorithm);
            return kf.generatePublic(spec);
        }
        return null;
    }

    static Key getPrivateKey(String FileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream keyFIS = new FileInputStream(FileName);
        byte[] encKey = new byte[keyFIS.available()];
        if (keyFIS.read(encKey) != -1) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encKey);
            KeyFactory kf = KeyFactory.getInstance(encodingAlgorithm);
            return  kf.generatePrivate(spec);
        }
        return null;
    }

    static String signString(String sourceString, String privateKeyFileName) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance("MD5withRSA");
        PrivateKey privateKey = (PrivateKey) getPrivateKey(privateKeyFileName);
        privateSignature.initSign(privateKey);
        privateSignature.update(sourceString.getBytes());
        byte[] signature = privateSignature.sign();

        String signatureID = UUID.randomUUID().toString();
        FileOutputStream fileFOS = new FileOutputStream("signatures/" + signatureID);
        fileFOS.write(signature);

        return signatureID;
    }

    static boolean checkSignature(String sourceString, String signatureFileName, String publicKeyFileName) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("MD5withRSA");
        PublicKey publicKey = (PublicKey) getPublicKey(publicKeyFileName);
        publicSignature.initVerify(publicKey);
        publicSignature.update(sourceString.getBytes());

        FileInputStream signFIS = new FileInputStream("signatures/" + signatureFileName);
        byte[] signature = new byte[signFIS.available()];
        signFIS.read(signature);

        return publicSignature.verify(signature);
    }

    static String encodeFile(String encFileName, String publicKeyFileName) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        FileInputStream encodingFIS = new FileInputStream(encFileName);
        byte[] encodingBytes = new byte[encodingFIS.available()];
        int dotIndex = encFileName.indexOf(".");
        String encodedFileName;
        if (dotIndex != -1)
            encodedFileName = encFileName.substring(0, dotIndex) + "_encoded" + encFileName.substring(dotIndex);
        else
            encodedFileName = encFileName + "_encoded";

        Cipher cipher = Cipher.getInstance(encodingAlgorithm);
        Key publicKey = getPublicKey(publicKeyFileName);
        if ((publicKey != null) && (encodingFIS.read(encodingBytes) != -1)) {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encodedBytes;
            //if (encodingBytes.length <= chunkSizeToEncrypt)
                encodedBytes = cipher.doFinal(encodingBytes);
            /*else {
                encodedBytes = new byte[encodingBytes.length + 11];
                byte[][] splittedBytes = splitArray(encodingBytes);
                int destPos = 0;
                for(byte[] b : splittedBytes) {
                    byte[] encodedChunk = cipher.doFinal(b);
                    System.arraycopy(encodedChunk, 0, encodedBytes, destPos, b.length);
                    destPos += encodedChunk.length;
                }
            }*/
            FileOutputStream fileFOS = new FileOutputStream(encodedFileName);
            fileFOS.write(encodedBytes);
            fileFOS.close();
            return encodedFileName;
        }
        encodingFIS.close();
        return null;
    }

    static String decodeArray(String decFileName, String privateKeyFileName) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        FileInputStream decodingFIS = new FileInputStream(decFileName);
        byte[] decodingBytes = new byte[decodingFIS.available()];
        Key privateKey = getPrivateKey(privateKeyFileName);

        if( (decodingFIS.read(decodingBytes) != -1) && (privateKey != null) ) {
            Cipher cipher = Cipher.getInstance(encodingAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decodedBytes = cipher.doFinal(decodingBytes);
            return new String(decodedBytes);
        }
        return null;
    }

    /*private static byte[][] splitArray(byte[] arrayToSplit){
        int chunkSize = chunkSizeToEncrypt;
        if(chunkSize<=0){
            return null;  // just in case :)
        }
        // first we have to check if the array can be split in multiple
        // arrays of equal 'chunk' size
        int rest = arrayToSplit.length % chunkSize;  // if rest>0 then our last array will have less elements than the others
        // then we check in how many arrays we can split our input array
        int chunks = arrayToSplit.length / chunkSize + (rest > 0 ? 1 : 0); // we may have to add an additional array for the 'rest'
        // now we know how many arrays we need and create our result array
        byte[][] arrays = new byte[chunks][];
        // we create our resulting arrays by copying the corresponding
        // part from the input array. If we have a rest (rest>0), then
        // the last array will have less elements than the others. This
        // needs to be handled separately, so we iterate 1 times less.
        for(int i = 0; i < (rest > 0 ? chunks - 1 : chunks); i++){
            // this copies 'chunk' times 'chunkSize' elements into a new array
            arrays[i] = Arrays.copyOfRange(arrayToSplit, i * chunkSize, i * chunkSize + chunkSize);
        }
        if(rest > 0){ // only when we have a rest
            // we copy the remaining elements into the last chunk
            arrays[chunks - 1] = Arrays.copyOfRange(arrayToSplit, (chunks - 1) * chunkSize, (chunks - 1) * chunkSize + rest);
        }
        return arrays; // that's it
    }*/

}
