package com.evan.cryptography.base64;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

/**
 * Base64算法使用
 *
 * @author Evan Huang
 * @date 2018/10/9
 */
@Slf4j
public class Base64Demo {

    private static final String SRC = "Hello base64";

    private static void jdkBase64() throws IOException {
        log.info("---------------------jdkBase64---------------------");

        BASE64Encoder encoder = new BASE64Encoder();
        String encode = encoder.encode(SRC.getBytes());
        log.info("encode:{}", encode);

        BASE64Decoder decoder = new BASE64Decoder();
        byte[] decodeBytes = decoder.decodeBuffer(encode);
        log.info("decode:{}", new String(decodeBytes));

        log.info("---------------------------------------------------\n");
    }

    private static void commonsCodesBase64() {
        log.info("---------------------commonsCodesBase64---------------------");

        byte[] encodeBytes = Base64.encodeBase64(SRC.getBytes());
        log.info("encode:{}", new String(encodeBytes));

        byte[] decodeBytes = Base64.decodeBase64(encodeBytes);
        log.info("decode:{}", new String(decodeBytes));

        log.info("---------------------------------------------------\n");
    }

    private static void bouncyCastleBase64() {
        log.info("---------------------bouncyCastleBase64---------------------");

        byte[] encodeBytes = org.bouncycastle.util.encoders.Base64.encode(SRC.getBytes());
        log.info("encode:{}", new String(encodeBytes));

        byte[] decodeBytes = org.bouncycastle.util.encoders.Base64.decode(encodeBytes);
        log.info("decode:{}", new String(decodeBytes));

        log.info("---------------------------------------------------\n");
    }

    public static void main(String[] args) throws Exception {
        jdkBase64();
        commonsCodesBase64();
        bouncyCastleBase64();
    }
}
