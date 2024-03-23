package com.piotrholda.spring.webflux.jwt.security;

import com.piotrholda.spring.webflux.jwt.TokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

@Service
class JwtService implements TokenProvider {

    @Value("${jwt.secret-key}")
    private String secretKey;

    @Value("${jwt.token-expiration-seconds}")
    private long tokenExpiration;

    String extractUsername(String token) {//notsure how this method extracts username, I believe it's true the method getSubect.
        return extractClaim(token, Claims::getSubject);
    }

    /*List<String> extractRoles(String jwt) {//removed
        return extractClaim(jwt, claims -> (List<String>) claims.get("roles"));
    }*/

    public List<String> extractRoles(String token) {//added //more convinient way to convert object to List<String>
        return extractClaim(token, claims -> {
            Object rolesObj = claims.get("roles");
            List<String> roles = new ArrayList<>();
            if (rolesObj instanceof ArrayList) {
                Arrays.stream((Object[]) rolesObj)
                    .map(Object::toString)
                    .forEach(roles::add);
            } 
            else {//this must be modified to throw an exception
                System.out.println("roles: "+rolesObj);
                // Handle the case when roles are not present or not in the expected format
                return null; // or throw an exception
            }
            return roles;
        });
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        return generateToken(Map.of(), userDetails);
    }

    /*boolean isTokenValid(String token) {//this methiod may be useless //removed and recreate with more stratigcal way
        return !isTokenExpired(token);
    }*/

    boolean isTokenValid(String token, UserDetails userDetails) {//added
        String username = extractUsername(token);
        return userDetails.getUsername().equals(username) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        long currentTimeMillis = System.currentTimeMillis();
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .claim("roles", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .map(role -> role.substring("ROLE_".length()))
                        .toArray())
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(currentTimeMillis + tokenExpiration * 1000))
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            throw new JwtAuthenticationException(e.getMessage());
        }
    }

    private SecretKey getSigningKey() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(bytes);
    }
}
