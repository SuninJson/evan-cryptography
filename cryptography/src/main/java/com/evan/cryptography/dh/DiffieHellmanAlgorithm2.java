package com.evan.cryptography.dh;


import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * DH密钥交换算法
 *
 * @author Evan Huang
 * @date 2018/10/11
 */
public class DiffieHellmanAlgorithm2 {

    private static final String DIFFIE_HELLMAN_ALGORITHM = "DH";
    private static final String DATA_ENCRYPT_STANDARD = "DES";


    private static final String MESSAGE = "Hello Diffie-Hellman Algorithm!";

    public static void main(String[] args) {
        jdkDH();
    }

    public static void jdkDH() {

        try {
            //发送方初始化密钥对
            KeyPair senderKeyPair = initSenderKeyPair();
            byte[] senderPublicKeyEncode = senderKeyPair.getPublic().getEncoded();

            //todo 接收方根据发送方公钥编码获取接收方密钥对和DES密钥
            KeyFactory receiverKeyFactory = KeyFactory.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            //将获取到的发送方公钥编码通过X.509标准标准化
            X509EncodedKeySpec senderPublicKeySpec = new X509EncodedKeySpec(senderPublicKeyEncode);
            //根据发送方标准化的公钥生成接收方公钥
            PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(senderPublicKeySpec);
            //获取标准化的本地公钥
            DHParameterSpec localPublicKeySpec = ((DHPublicKey) receiverPublicKey).getParams();
            //通过标准化的接收方公钥生成接受方密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            keyPairGenerator.initialize(localPublicKeySpec);
            KeyPair receiverKeyPair = keyPairGenerator.generateKeyPair();
            byte[] receiverPublicKeyEncode = receiverKeyPair.getPublic().getEncoded();

            KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            receiverKeyAgreement.init(receiverKeyPair.getPrivate());
            receiverKeyAgreement.doPhase(receiverPublicKey, true);
            SecretKey receiverDesKey = receiverKeyAgreement.generateSecret(DATA_ENCRYPT_STANDARD);

            //todo 通过接收方公钥编码获取发送方DES密钥
            KeyFactory senderKeyFactory = KeyFactory.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            //将获取到的发送方公钥编码通过X.509标准标准化
            X509EncodedKeySpec receiverPublicKeySpec = new X509EncodedKeySpec(receiverPublicKeyEncode);
            PublicKey senderPublicKey = senderKeyFactory.generatePublic(receiverPublicKeySpec);

            KeyAgreement senderKeyAgreement = KeyAgreement.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            senderKeyAgreement.init(senderKeyPair.getPrivate());
            senderKeyAgreement.doPhase(senderPublicKey, true);
            SecretKey senderDesKey = senderKeyAgreement.generateSecret(DATA_ENCRYPT_STANDARD);

            System.out.println(
                    "发送方DES密钥为：" + Base64.encodeBase64String(senderDesKey.getEncoded()) + "\n"
                            + "接收方DES密钥为：" + Base64.encodeBase64String(receiverDesKey.getEncoded()) + "\n"
            );

            if (Objects.equals(senderDesKey, receiverDesKey)) {
                System.out.println("发送方DES密钥与接收方DES密钥相同");
            }

            //发送方使用本地密钥加密
            Cipher dhCipher = Cipher.getInstance(DATA_ENCRYPT_STANDARD);
            dhCipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
            byte[] encryptMessageEncode = dhCipher.doFinal(MESSAGE.getBytes());
            System.out.println("发送方加密后的信息：" + Base64.encodeBase64String(encryptMessageEncode));

            //接收方使用本地密钥解密
            dhCipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
            byte[] messageEncode = dhCipher.doFinal(encryptMessageEncode);
            System.out.println("接收方解密后的信息：" + new String(messageEncode));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 初始化发送方密钥对（公钥、私钥）
     */
    private static KeyPair initSenderKeyPair() {
        KeyPair senderKeyPair = null;

        try {
            KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance(DIFFIE_HELLMAN_ALGORITHM);

            //DH算法的密钥长度范围为512~1024区间中64的倍数
            senderKeyPairGenerator.initialize(512);
            senderKeyPair = senderKeyPairGenerator.genKeyPair();
            PublicKey publicKey = senderKeyPair.getPublic();
            PrivateKey privateKey = senderKeyPair.getPrivate();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return senderKeyPair;
    }

}
