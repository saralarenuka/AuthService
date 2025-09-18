package com.example.authservice.service;

import com.example.authservice.entity.AuthRequest;

public interface AuthService {
    String authenticate(AuthRequest request);
}
