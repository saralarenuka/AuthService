package com.example.authservice.filter;

import com.example.authservice.service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.GrantedAuthority;


import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
                                    throws ServletException, IOException {
     System.out.println("Request URI: " + request.getRequestURI());
     
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;
        String path = request.getRequestURI();
        if (path.equals("/auth/login") || path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.startsWith("/h2-console")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // Extract token and username
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            try {
                username = jwtService.extractUsername(token);
            } catch (Exception e) {
                // Optional: log or handle invalid token
                username = null;
            }
           
        }

        // Validate and set authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (jwtService.validateToken(token, username)) {
//                UsernamePasswordAuthenticationToken authToken =
//                    new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
            	
            	Claims claims = Jwts.parserBuilder()
            		    .setSigningKey(jwtService.getSigningKey())
            		    .build()
            		    .parseClaimsJws(token)
            		    .getBody();

            		String role = claims.get("role", String.class);
            		List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role)); // Role based authority

            		UsernamePasswordAuthenticationToken authToken =
            		    new UsernamePasswordAuthenticationToken(username, null, authorities);
            		authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            		SecurityContextHolder.getContext().setAuthentication(authToken);


                // This line is crucial for Spring Security 6
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
 
    }
}
