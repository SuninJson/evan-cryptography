package com.evan.cryptography.rsa;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA非对称加密算法
 *
 * @author Evan Huang
 * @date 2018/10/15
 */
@Slf4j
public class RsaDemo {

    private static final String RSA = "RSA";

    public static void main(String[] args) {

        try {
            //初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("公钥：" + Base64.encodeBase64String(publicKey.getEncoded()));
            System.out.println("私钥：" + Base64.encodeBase64String(privateKey.getEncoded()) + "\n");

            //发送方使用私钥加密数据发送给接收方
            PKCS8EncodedKeySpec privateKeyEncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            KeyFactory senderKeyFactory = KeyFactory.getInstance(RSA);
            PrivateKey privateKeySpec = senderKeyFactory.generatePrivate(privateKeyEncodedKeySpec);

            String reqMessage = "Hello,I'm sender!";

            Cipher senderCipher = Cipher.getInstance(RSA);
            senderCipher.init(Cipher.ENCRYPT_MODE, privateKeySpec);
            byte[] reqMessageEncode = senderCipher.doFinal(reqMessage.getBytes());
            System.out.println("发送方通过私钥加密后的请求信息编码：" + Base64.encodeBase64String(reqMessageEncode));

            //接收方使用公钥解密数据
            X509EncodedKeySpec publicKeyEncodedSpec = new X509EncodedKeySpec(publicKey.getEncoded());
            KeyFactory receiverKeyFactory = KeyFactory.getInstance(RSA);
            PublicKey publicKeySpec = receiverKeyFactory.generatePublic(publicKeyEncodedSpec);

            Cipher receiverCipher = Cipher.getInstance(RSA);
            receiverCipher.init(Cipher.DECRYPT_MODE, publicKeySpec);
            byte[] reqMessageBytes = receiverCipher.doFinal(reqMessageEncode);
            System.out.println("接收方通过公钥解密后的信息：" + new String(reqMessageBytes) + "\n");

            //接收方使用公钥加密返回信息给发送方
            String respMessage = "Hello sender,I'm receiver!";

            receiverCipher.init(Cipher.ENCRYPT_MODE, publicKeySpec);
            byte[] respMessageBytes = receiverCipher.doFinal(respMessage.getBytes());
            System.out.println("接收方通过公钥加密后的返回信息编码：" + Base64.encodeBase64String(respMessageBytes));

            //发送方使用私钥解密返回信息
            senderCipher.init(Cipher.DECRYPT_MODE, privateKeySpec);
            byte[] respMessageEncode = senderCipher.doFinal(respMessageBytes);
            System.out.println("发送方通过私钥解密后的返回信息：" + new String(respMessageEncode));

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
