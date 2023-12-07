package org.bci.configurations;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.bci.models.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Component
public class JwtUtil {

    private final JwtParser jwtParser;
    private final String SECRET_KEY = "mysecretkey";
    private final long TOKEN_EXPIRATION = 60000; //60 * 60 * 1000; // 1 hour
    private final String TOKEN_HEADER = "Authorization";
    private final String TOKEN_PREFIX = "Bearer ";

    public JwtUtil() {
        this.jwtParser = Jwts.parser().setSigningKey(SECRET_KEY);
    }

    public String createToken(User user) {
        Claims claims = Jwts.claims().setSubject(user.getEmail());
        claims.put("id", user.getId());
        claims.put("name", user.getName());
        claims.put("password", user.getPassword());

        Date tokenCreateTime = new Date();
        Date tokenValidity = new Date(tokenCreateTime.getTime() + TOKEN_EXPIRATION);

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(tokenValidity)
                .signWith(HS256, SECRET_KEY)
                .compact();
    }

    private Claims parseJwtClaims(String token) {
        return jwtParser.parseClaimsJws(token).getBody();
    }

    public String resolveToken(HttpServletRequest request) {
        var bearerToken = request.getHeader(TOKEN_HEADER);
        if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

    public Claims resolveClaims(HttpServletRequest req) {
        var token = resolveToken(req);
        if (token != null) {
            return parseJwtClaims(token);
        }
        return null;
    }

    private boolean validateClaims(String token) {
        final Date expiration = parseJwtClaims(token).getExpiration();
        return expiration.after(new Date());
    }

    public String getUsername(String token) {
        return parseJwtClaims(token).getSubject();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsername(token);
        return (username.equals(userDetails.getUsername()) && validateClaims(token));
    }
}
