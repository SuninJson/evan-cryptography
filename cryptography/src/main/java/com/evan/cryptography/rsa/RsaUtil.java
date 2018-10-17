package com.evan.cryptography.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * @author Evan Huang
 * @date 2018/10/15
 */
public class RsaUtil {

    public static final String RSA = "RSA";

    /**
     * 利用RSA算法构建密钥对
     */
    public static KeyPair getRsaKeyPair() {
        try {
            //发送方构建密钥对
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(512);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
