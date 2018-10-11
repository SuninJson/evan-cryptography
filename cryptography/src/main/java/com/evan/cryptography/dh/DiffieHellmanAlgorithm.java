package com.evan.cryptography.dh;


import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * DH密钥交换算法
 *
 * @author Evan Huang
 * @date 2018/10/11
 */
public class DiffieHellmanAlgorithm {

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
            for (byte b : senderKeyPair.getPrivate().getEncoded()) {
                System.out.print(b);
            }
            System.out.println();

            //接收方根据发送方公钥初始化接收方密钥对
            KeyPair receiverKeyPair = initLocalKeyPairByPublicKeyEncode(senderPublicKeyEncode);
            byte[] receiverPublicKeyEncode = receiverKeyPair.getPublic().getEncoded();

            //接收方根据发送方公钥编码获取接收方DES密钥
            SecretKey receiverDesKey = getDesKey(receiverKeyPair, senderPublicKeyEncode);

            //发送方根据接收方公钥编码获取发送方DES密钥
            SecretKey senderDesKey = getDesKey(senderKeyPair, receiverPublicKeyEncode);

            System.out.println(
                    "发送方DES密钥为：" + Base64.encodeBase64String(senderDesKey.getEncoded()) + "\n"
                            + "接收方DES密钥为：" + Base64.encodeBase64String(receiverDesKey.getEncoded()) + "\n"
            );

            if (Objects.equals(senderDesKey, receiverDesKey)) {
                System.out.println("发送方DES密钥与接收方DES密钥相同");
            }

            //发送方使用本地密钥加密
            byte[] senderMessageEncode = desEncrypt(senderDesKey, MESSAGE);
            System.out.println("发送方加密后的信息：" + Base64.encodeBase64String(senderMessageEncode));

            //接收方使用本地密钥解密
            byte[] receiverMessageEncode = desDecrypt(receiverDesKey, senderMessageEncode);
            System.out.println("接收方解密后的信息：" + new String((receiverMessageEncode)));

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
        } catch (Exception e) {
            e.printStackTrace();
        }

        return senderKeyPair;
    }

    /**
     * 根据远程公钥编码初始化本地密钥对
     */
    private static KeyPair initLocalKeyPairByPublicKeyEncode(byte[] remotePublicKeyEncode) {
        KeyPair localKeyPair = null;
        try {
            //将获取到的发送方公钥编码通过X.509标准标准化
            X509EncodedKeySpec remotePublicKeySpec = new X509EncodedKeySpec(remotePublicKeyEncode);

            //根据发送方标准化的公钥生成接收方公钥
            KeyFactory dhKeyFactory = KeyFactory.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            DHPublicKey localPublicKey = (DHPublicKey) dhKeyFactory.generatePublic(remotePublicKeySpec);

            //获取标准化的接受方公钥
            DHParameterSpec localPublicKeySpec = localPublicKey.getParams();

            //通过标准化的接收方公钥生成接受方密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            keyPairGenerator.initialize(localPublicKeySpec);
            localKeyPair = keyPairGenerator.generateKeyPair();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return localKeyPair;
    }

    /**
     * 根据远程公钥编码获取本地DES密钥
     *
     * @param keyPair
     * @param remotePublicKeyEncode 远程公钥编码
     * @return DES密钥
     */
    private static SecretKey getDesKey(KeyPair keyPair, byte[] remotePublicKeyEncode) {
        SecretKey desKey = null;
        try {
            //将获取到的发送方公钥编码通过X.509标准标准化
            X509EncodedKeySpec remotePublicKeySpec = new X509EncodedKeySpec(remotePublicKeyEncode);
            //根据发送方标准化的公钥生成接收方公钥
            KeyFactory dhKeyFactory = KeyFactory.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            DHPublicKey localSpecPublicKey = (DHPublicKey) dhKeyFactory.generatePublic(remotePublicKeySpec);

            //通过DES（数据加密标准）标准化本地密钥
            KeyAgreement dhKeyAgreement = KeyAgreement.getInstance(DIFFIE_HELLMAN_ALGORITHM);
            dhKeyAgreement.init(keyPair.getPrivate());
            dhKeyAgreement.doPhase(localSpecPublicKey, true);
            desKey = dhKeyAgreement.generateSecret(DATA_ENCRYPT_STANDARD);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return desKey;
    }

    /**
     * @param desKey  DES密钥
     * @param message 需要加密的信息
     * @return 加密后的信息编码
     */
    private static byte[] desEncrypt(SecretKey desKey, String message) {
        byte[] encryptMessageEncode = null;
        try {
            Cipher dhCipher = Cipher.getInstance(DATA_ENCRYPT_STANDARD);
            dhCipher.init(Cipher.ENCRYPT_MODE, desKey);
            encryptMessageEncode = dhCipher.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptMessageEncode;
    }

    /**
     * @param desKey        DES密钥
     * @param messageEncode 需要解密的信息
     * @return 解密后的信息编码
     */
    private static byte[] desDecrypt(SecretKey desKey, byte[] messageEncode) {
        byte[] encryptMessageEncode = null;
        try {
            Cipher dhCipher = Cipher.getInstance(DATA_ENCRYPT_STANDARD);
            dhCipher.init(Cipher.DECRYPT_MODE, desKey);
            encryptMessageEncode = dhCipher.doFinal(messageEncode);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptMessageEncode;
    }
}
