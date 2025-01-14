package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;


@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable) // CSRF 비활성화 (개발 단계)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll() // 모든 요청 허용 (개발 단계)
                )
                .formLogin(form -> form // 일반 로그인 설정
                        .defaultSuccessUrl("/") // 로그인 성공 시 이동할 기본 URL
                        .permitAll() // 로그인 페이지는 인증 없이 접근 가능
                )
                .logout(logout -> logout // 로그아웃 설정
                        .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동할 URL
                        .permitAll()
                )
                .build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}