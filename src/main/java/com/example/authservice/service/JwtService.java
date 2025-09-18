package com.example.authservice.service;

import java.security.Key;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;


@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expirationTime;

//    public Key getSigningKey() {
//        byte[] keyBytes = secretKey.getBytes();
//        return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
//    }
    
	/*
	 * public Key getSigningKey() { return Keys.hmacShaKeyFor(secretKey.getBytes());
	 * // Uses secure key length }
	 */
    public Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(
                io.jsonwebtoken.io.Encoders.BASE64.encode(secret.getBytes())
        );
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String username, String userRole) {
        long expirationTime = 3600000; // 1 hour or inject via @Value

        return Jwts.builder()
                .setSubject(username)
                // Store roles as a List for easier parsing
                .claim("roles", List.of(userRole))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

	/*
	 * public String generateToken(String username,String userRoles) { return
	 * Jwts.builder() .setSubject(username) // .claim("role", role) // Embed role in
	 * token //.claim("roles", userRoles) claims.put("roles",
	 * List.of(user.getRole())); .setIssuedAt(new Date()) .setExpiration(new
	 * Date(System.currentTimeMillis() + expirationTime)) .signWith(getSigningKey(),
	 * SignatureAlgorithm.HS256) .compact(); }
	 */

    public String extractUsername(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getSigningKey())
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public boolean validateToken(String token, String username) {
        try {
            return extractUsername(token).equals(username);
        } catch (Exception e) {
            return false;
        }
    }
}
