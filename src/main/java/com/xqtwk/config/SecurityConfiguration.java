package com.xqtwk.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.filter.CorsFilter;

import static com.xqtwk.user.Permission.*;
import static com.xqtwk.user.Role.*;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private static final String[] WHITE_LIST = {
            "/auth/**",
            "/"
    };

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;
    private final CorsFilter corsFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req -> req.requestMatchers(WHITE_LIST)
                        .permitAll()
                        .requestMatchers("/management/**").hasAnyRole(ADMIN.name(), MODERATOR.name())
                        .requestMatchers(GET, "/management/**").hasAnyAuthority(ADMIN_READ.name(), MODERATOR_READ.name())
                        .requestMatchers(POST, "/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MODERATOR_CREATE.name())
                        .requestMatchers(PUT, "/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MODERATOR_UPDATE.name())
                        .requestMatchers(DELETE, "/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MODERATOR_DELETE.name())

                        .requestMatchers("/admin/**").hasRole(ADMIN.name())
                        .requestMatchers(GET, "/admin/**").hasAuthority(ADMIN_READ.name())
                        .requestMatchers(POST, "/admin/**").hasAuthority(ADMIN_CREATE.name())
                        .requestMatchers(PUT, "/admin/**").hasAuthority(ADMIN_UPDATE.name())
                        .requestMatchers(DELETE, "/admin/**").hasAuthority(ADMIN_DELETE.name())
                        .anyRequest()
                        .authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout ->
                        logout.logoutUrl("/auth/logout")
                                .addLogoutHandler(logoutHandler)
                                .logoutSuccessHandler(((request, response, authentication) -> SecurityContextHolder.clearContext()))
                );


        return http.build();
    }
}
