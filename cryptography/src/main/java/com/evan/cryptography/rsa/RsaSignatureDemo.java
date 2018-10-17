package com.evan.cryptography.rsa;


import org.apache.commons.codec.binary.Hex;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA算法实现数字签名
 *
 * @author Evan Huang
 * @date 2018/10/15
 */
public class RsaSignatureDemo {

    public static void main(String[] args) {

        try {
            //发送方构建并公布密钥对
            KeyPair rsaKeyPair = RsaUtil.getRsaKeyPair();
            if (rsaKeyPair != null) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();

                //发送方使用私钥进行数据签名
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
                KeyFactory keyFactory = KeyFactory.getInstance(RsaUtil.RSA);
                PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

                String mySignature = "Evan Huang";

                Signature signature = Signature.getInstance("MD5withRSA");
                signature.initSign(privateKey);
                signature.update(mySignature.getBytes());
                byte[] signedMessage = signature.sign();
                System.out.println("发送方进行数据签名的信息(十六进制)：" + Hex.encodeHexString(signedMessage));

                //接收方使用公钥验证签名信息
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
                PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

                signature = Signature.getInstance("MD5withRSA");
                signature.initVerify(publicKey);
                signature.update(mySignature.getBytes());
                boolean verifyResult = signature.verify(signedMessage);
                System.out.println("接收方使用公钥和签名验证后结果：" + verifyResult);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
