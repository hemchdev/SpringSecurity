package com.spring_basic_security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * SecurityConfig class is responsible for configuring Spring Security for the application.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Configures the security filter chain to define the security behavior of the application.
     *
     * @param http the HttpSecurity object for configuring security settings
     * @return the configured SecurityFilterChain
     * @throws Exception in case of any configuration issues
     */
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));




//        // Disable CSRF protection for simplicity in certain use cases (not recommended in production).
//        http.csrf(customizer -> customizer.disable());
//
//        // Restrict all requests to be authenticated unless explicitly allowed.
//        http.authorizeHttpRequests(request -> request.anyRequest().authenticated());
//
//        // Enable default form-based login for authentication.
//        http.formLogin(Customizer.withDefaults());
//
//        // Enable HTTP Basic authentication.
//        http.httpBasic(Customizer.withDefaults());
//
//        // Configure session management to be stateless.
//        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Build and return the SecurityFilterChain.
        return http.build();
    }
}
