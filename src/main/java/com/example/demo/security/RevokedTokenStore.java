package com.example.demo.security;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class RevokedTokenStore {

    private static final Set<String> revoked = ConcurrentHashMap.newKeySet();

    public static void revoke(String jti) {
        revoked.add(jti);
    }

    public static boolean isRevoked(String jti) {
        return revoked.contains(jti);
    }
}
