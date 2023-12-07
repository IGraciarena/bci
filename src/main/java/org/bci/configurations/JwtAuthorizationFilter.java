package org.bci.configurations;

import io.jsonwebtoken.Claims;
import org.bci.service.impl.UserDetailServiceImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserDetailServiceImpl userDetailService;

    public JwtAuthorizationFilter(JwtUtil jwtUtil,
                                  UserDetailServiceImpl userDetailService) {
        this.jwtUtil = jwtUtil;
        this.userDetailService = userDetailService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        var accessToken = jwtUtil.resolveToken(request);
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }
        Claims claims = jwtUtil.resolveClaims(request);
        if (claims != null) {
            var user = userDetailService.loadUserByUsername(jwtUtil.getUsername(accessToken));
            if (jwtUtil.validateToken(accessToken, user)) {
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(),
                        claims.get("password"),
                        new ArrayList<>()
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
