package com.auth.jwt_auth.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUnit {

    private static final Logger logger =
            LoggerFactory.getLogger(JwtUnit.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    private SecretKey key;


    // Runs automatically after @Value variables are injected
    @PostConstruct
    public void init() {

        this.key = Keys.hmacShaKeyFor(
                jwtSecret.getBytes(StandardCharsets.UTF_8)
        );
    }


    // Generate JWT Token
    public String generateSecretKey(String username , String email) {

        return Jwts.builder()
                .subject(username)
                .claim("email" , email)
                .issuedAt(new Date())
                .expiration(
                        new Date(
                                System.currentTimeMillis() + jwtExpiration
                        )
                )
                .signWith(key)
                .compact();
    }


    // Get username from JWT Token
    public String getUsernameFromToken(String token) {

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    //Get email form the token
    public String getEmailFromToken(String token) {

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("email", String.class);
    }


    // Validate JWT Token
    public boolean validateJwtToken(String token) {

        try {

            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);

            return true;

        } catch (JwtException | IllegalArgumentException e) {

            logger.info(
                    "Invalid JWT: {}",
                    e.getMessage()
            );

            return false;
        }
    }
}