package com.evan.cryptography.dh;

import lombok.Data;

import javax.crypto.SecretKey;
import java.security.KeyPair;

/**
 * @author Evan Huang
 * @date 2018/10/11
 */
@Data
public class DiffieHellmanKey {
    private KeyPair keyPair;
    private SecretKey desKey;
}
