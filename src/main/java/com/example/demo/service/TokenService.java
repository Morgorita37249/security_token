package com.example.demo.service;

import com.example.demo.security.KeyLoader;
import com.example.demo.security.RevokedTokenStore;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import org.springframework.stereotype.Service;
import java.security.interfaces.*;
import java.util.Date;

@Service
public class TokenService {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public TokenService() {
        try {
            this.privateKey = KeyLoader.loadPrivateKey("src/main/resources/private.pem");
            this.publicKey = KeyLoader.loadPublicKey("src/main/resources/public.pem");
        } catch (Exception e) {
            throw new RuntimeException("Не удалось загрузить ключи", e);
        }
    }

    public String generateEncryptedToken() throws Exception {
        JWSSigner signer = new RSASSASigner(privateKey);
        Date now = new Date();
        Date exp = new Date(now.getTime() + 10 * 60 * 1000); // 10 минут
        String jti = java.util.UUID.randomUUID().toString();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user123")
                .issuer("my-app")
                .claim("role", "user")
                .issueTime(now)
                .expirationTime(exp)
                .jwtID(jti)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                claimsSet);

        signedJWT.sign(signer);

        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .build(),
                new Payload(signedJWT));

        jweObject.encrypt(new RSAEncrypter(publicKey));

        return jweObject.serialize();
    }

    public String decryptAndValidate(String token) throws Exception {
        JWEObject jweObject = JWEObject.parse(token);
        jweObject.decrypt(new RSADecrypter(privateKey));

        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        if (!signedJWT.verify(verifier)) {
            throw new Exception("Invalid signature");
        }

        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        Date now = new Date();
        if (claims.getExpirationTime() == null || now.after(claims.getExpirationTime())) {
            throw new Exception("Token expired");
        }
        String jti = claims.getJWTID();
        if (RevokedTokenStore.isRevoked(jti)) {
            throw new Exception("Token has been revoked");
        }

        return "Access granted for user: " + claims.getSubject() + " with role: " + claims.getStringClaim("role");

    }
    public JWTClaimsSet extractClaims(String encryptedToken) throws Exception {
        JWEObject jweObject = JWEObject.parse(encryptedToken);
        jweObject.decrypt(new RSADecrypter(privateKey));
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
        return signedJWT.getJWTClaimsSet();
    }

}
