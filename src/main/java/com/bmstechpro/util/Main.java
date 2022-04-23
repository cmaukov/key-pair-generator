package com.bmstechpro.util;
/* key-pair-generator
 * @created 04/22/2022
 * @author Konstantin Staykov
 */


import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {
        try {
            // Generating key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(512);
            KeyPair generatedKeyPair = keyPairGenerator.genKeyPair();

            // dump the key pair
            dumpKeyPair(generatedKeyPair);

            // Keys to byte arrays
            byte[] privateKeyByteArray = generatedKeyPair.getPrivate().getEncoded();
            byte[] publicKeyByteArray = generatedKeyPair.getPublic().getEncoded();

            // Getting keys from byte arrays
            PrivateKey privateKey = getPrivateKey(privateKeyByteArray);
            PublicKey publicKey = getPublicKey(publicKeyByteArray);

            // Signing a string
            // Creating a signature
            Signature sign = Signature.getInstance("DSA");

            //Initialize the signature
            sign.initSign(privateKey);

            // byte array of the string we are going to sign
            byte[] dataToSign = "helloWorld".getBytes();

            //Adding data to the signature
            sign.update(dataToSign);

            //Calculating the signature
            byte[] signature = sign.sign();

            byte[] encode = Base64.getEncoder().encode(signature);
            //Printing the signature
            System.out.println("Digital signature for given text: " + new String(encode));

            // Signature Verification
            byte[] signBytes = Base64.getDecoder().decode(encode);
            System.out.println("Verified: " + verify(dataToSign, signBytes, publicKeyByteArray));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void dumpKeyPair(KeyPair generatedKeyPair) {
        PublicKey publicKey = generatedKeyPair.getPublic();
        System.out.println("Public Key: " + Arrays.toString(publicKey.getEncoded()));

        PrivateKey privateKey = generatedKeyPair.getPrivate();
        System.out.println("Private Key: " + Arrays.toString(privateKey.getEncoded()));
    }


    private static PublicKey getPublicKey(byte[] pubCode) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(pubCode));
    }

    private static PrivateKey getPrivateKey(byte[] privateCode) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateCode));
    }

    private static boolean verify(byte[] input, byte[] signKey, byte[] publicKeyByteArray) throws Exception {
        Signature verSign = Signature.getInstance("DSA");
        verSign.initVerify(getPublicKey(publicKeyByteArray));
        verSign.update(input);
        return verSign.verify(signKey);
    }


}
