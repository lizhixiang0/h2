package com.zx.arch.strategy;//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//


import java.net.Socket;
import java.util.Map;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;

/**
 * @author admin
 */
public class DefaultPrivateKeyStrategy implements PrivateKeyStrategy {
    private String keyAlias;

    public DefaultPrivateKeyStrategy(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    @Override
    public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
        return this.keyAlias;
    }
}

