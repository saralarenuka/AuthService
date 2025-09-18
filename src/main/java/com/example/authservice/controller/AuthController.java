package com.example.authservice.controller;

import com.example.authservice.entity.AuthRequest;
import com.example.authservice.entity.AuthResponse;
import com.example.authservice.service.AuthService;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;

//import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

//import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;


@RestController
@RequestMapping("/auth")
@SecurityRequirement(name = "BearerAuth") // Applies to all endpoints in this controller
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
    	
    	System.out.println("Login attempt: " + request.getUsername());
        String token = authService.authenticate(request);
        return ResponseEntity.ok(new AuthResponse(token));
        
    }
   
  
    
}
