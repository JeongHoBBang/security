package com.green.security.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {
    private final Logger LOGGER = LoggerFactory.getLogger(JwtTokenProvider.class);
    private final UserDetailsService SERVICE;

    private final Key KEY;
    private final long TOKEN_VALID_MS = 3_600_000L; // 1000L * 60 * 60 -> 1시간

    @Autowired
    public JwtTokenProvider(@Value("${springboot.jwt.secret}") String secretKey, UserDetailsService service) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.KEY = Keys.hmacShaKeyFor(keyBytes);
        this.SERVICE = service;
    }


    public String generateJwtToken(String uid, List<String> roles) {
        LOGGER.info("JwtTokenProvider - generateJwtToken: 토큰 생성 시작");
        Date now = new Date();

        String token = Jwts.builder()
                .setClaims(createClaims(uid, roles))
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + TOKEN_VALID_MS))
                .signWith(KEY)
                .compact();
        LOGGER.info("JwtTokenProvider - generateJwtToken: 토큰 생성 완료");
        return token;
    }

    private Claims createClaims(String uid, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(uid);
        claims.put("roles", roles);
        return claims;
    }

    public Authentication getAuthentication (String token) {
        LOGGER.info("JwtTokenProvider - getAuthentication: 토큰 인증 정보 조회 시작");
        UserDetails userDetails = SERVICE.loadUserByUsername(getUsername(token));

        LOGGER.info("JwtTokenProvider - getAuthentication: 토큰 인증 정보 조회 완료, UserDetails UserName : {}"
                , userDetails.getUsername());
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    private String getUsername(String token) {
        return getClaims(token)
                .getSubject();
    }

    public String resolveToken(HttpServletRequest req, String type) {
        LOGGER.info("JwtTokenProvider - resolveToken: HTTP 헤더에서 Token 값 추출");
        String headerAuth = req.getHeader("Authorization");
        return headerAuth == null ? null : headerAuth.substring(type.length()).trim();
    }

    private Claims getClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isValidateToken(String token) {
        LOGGER.info("JwtTokenProvider - isValidateToken: 토큰 유효 체크 시작");
        try {
            return !getClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            LOGGER.info("JwtTokenProvider - isValidateToken: 토큰 유효 체크 예외 발생");
            return false;
        }
    }
}
