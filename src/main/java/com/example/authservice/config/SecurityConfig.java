package com.example.authservice.config;

import com.example.authservice.entity.User;
import com.example.authservice.filter.JwtFilter;
import com.example.authservice.repository.UserRepository;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    public SecurityConfig(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    	http
    	.authorizeHttpRequests(auth -> auth
    		    .requestMatchers(
    		        "/auth/login",
    		        "/swagger-ui/**",
    		        "/swagger-ui.html",
    		        "/v3/api-docs/**",
    		        "/h2-console/**"
    		    ).permitAll()

    		    // Role-based access control
    		    .requestMatchers(org.springframework.http.HttpMethod.GET, "/**").hasAnyRole("USER", "ADMIN")
    		    .requestMatchers(org.springframework.http.HttpMethod.POST, "/**").hasRole("ADMIN")
    		    .requestMatchers(org.springframework.http.HttpMethod.PUT, "/**").hasRole("ADMIN")
    		    .requestMatchers(org.springframework.http.HttpMethod.DELETE, "/**").hasRole("ADMIN")

    		    .anyRequest().authenticated()

        )
        .csrf(csrf -> csrf.disable())
        .headers(headers -> headers.frameOptions(frame -> frame.disable())) //  Needed for H2
        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
    
    // existing JwtFilter and SecurityFilterChain...

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

   // @Bean
    public CommandLineRunner seedUser(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByUsername("admin").isEmpty()) {
                User user = new User();
                user.setUsername("admin");
                user.setPassword(passwordEncoder.encode("admin123")); //  Encoded password
                user.setRole("ROLE_ADMIN");
                userRepository.save(user);
                System.out.println("Seeded default user: admin / admin123");
            }
        };
    }
    
    @Bean
    public CommandLineRunner seedUser2(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByUsername("user").isEmpty()) {
                User user = new User();
                user.setUsername("user");
                user.setPassword(passwordEncoder.encode("user123")); //  Encoded password
                user.setRole("ROLE_USER");
                userRepository.save(user);
                System.out.println("Seeded default user: user / user123");
            }
        };
    }


}
