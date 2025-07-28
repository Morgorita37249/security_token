package com.example.demo.controller;


import com.example.demo.service.TokenService;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api")
public class JWTController {

    private final TokenService tokenService;

    public JWTController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/token")
    public String getEncryptedToken() throws Exception {
        return tokenService.generateEncryptedToken();
    }

    @GetMapping("/secure")
    public ResponseEntity<String> access(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");

        try {
            String result = tokenService.decryptAndValidate(token);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Token invalid or expired: " + e.getMessage());
        }
    }
    @GetMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        try {
            JWTClaimsSet claims = tokenService.extractClaims(token);
            String jti = claims.getJWTID();
            com.example.demo.security.RevokedTokenStore.revoke(jti);
            return ResponseEntity.ok("Token revoked successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid token: " + e.getMessage());
        }
    }
}

