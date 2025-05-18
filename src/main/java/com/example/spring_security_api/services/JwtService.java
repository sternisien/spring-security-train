package com.example.spring_security_api.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

  private final SecretKey secretKey;

  public JwtService() throws NoSuchAlgorithmException {
    this.secretKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
  }

  public String generateToken(String username) {
    Map<String, Object> claims = new HashMap<>();
    Date now = new Date();
    Date expirationDate = Date.from(now.toInstant().plus(Duration.ofDays(2L)));
    return Jwts.builder()
        .claims()
        .add(claims)
        .subject(username)
        .issuedAt(now)
        .expiration(expirationDate)
        .and()
        .signWith(getSecretKey())
        .compact();
  }

  public boolean validateToken(String token) {
    Date expirationDate = extractExpirationDate(token);
    return expirationDate.after(new Date());
  }

  public String extractUsername(String token) {
    return extractSpecificClaim(token, Claims::getSubject);
  }

  public Date extractExpirationDate(String token) {
    return extractSpecificClaim(token, Claims::getExpiration);
  }

  private Key getSecretKey() {
    return Keys.hmacShaKeyFor(secretKey.getEncoded());
  }

  private <T> T extractSpecificClaim(String token, Function<Claims, T> claimResolver) {
    Claims allClaims = extractClaims(token);
    return claimResolver.apply(allClaims);
  }

  private Claims extractClaims(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
