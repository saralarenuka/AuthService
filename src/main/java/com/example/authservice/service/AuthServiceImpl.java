package com.example.authservice.service;

import com.example.authservice.entity.AuthRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public String authenticate(AuthRequest request) {
        System.out.println("Login attempt for username: " + request.getUsername());

        User user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> {
                System.out.println("User not found: " + request.getUsername());
                return new RuntimeException("User not found");
            });

        boolean passwordMatch = passwordEncoder.matches(request.getPassword(), user.getPassword());
        System.out.println(" Password match result: " + passwordMatch);

        if (passwordMatch) {
            String token = jwtService.generateToken(user.getUsername(), user.getRole());
            System.out.println(" Token generated for user: " + user.getUsername());
            return token;
        } else {
            System.out.println(" Invalid password for user: " + user.getUsername());
            throw new RuntimeException("Invalid credentials");
        }
    }
}
