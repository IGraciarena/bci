package org.bci.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static org.bci.utils.EntityUtils.USER_ENTITY_STUB;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
public final class AuthenticationTokenUtils {
    private AuthenticationTokenUtils() {
    }

    public static String getBearerToken() {
        final LocalDateTime ldNow = LocalDateTime.now();
        final LocalDateTime ldExpiration = ldNow.plus(Duration.ofMillis(60 * 60 * 1000));
        final Date now = Date.from(ldNow.atZone(ZoneId.systemDefault()).toInstant());
        final Date expirationDate = Date.from(ldExpiration.atZone(ZoneId.systemDefault()).toInstant());
        return Jwts.builder()
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, "mysecretkey")
                .claim("email", USER_ENTITY_STUB.getEmail())
                .claim("password", USER_ENTITY_STUB.getPassword())
                .compact();
    }


}
