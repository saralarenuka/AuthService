package com.example.authservice.repository;


import com.example.authservice.entity.User;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUsername(String username);

}
