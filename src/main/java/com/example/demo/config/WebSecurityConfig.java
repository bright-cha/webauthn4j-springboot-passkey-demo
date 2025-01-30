package com.example.demo.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.List;

@Configuration // Spring에서 설정 클래스로 인식
@EnableWebSecurity // Spring Security를 활성화
public class WebSecurityConfig {

    @Autowired // Spring 컨테이너에서 ApplicationContext를 주입
    private ApplicationContext applicationContext;

    // WebAuthn인증을 지원하는 AuthenticationProvider 빈 정의
    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnCredentialRecordService authenticatorService, WebAuthnManager webAuthnManager){
        // WebAuthnAuthenticationProvider: WebAuthn 프로세스(인증)를 처리하기 위한 Provider
        return new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }

    // DAO 기반(일반적인 Username/Password) 인증을 위한 Provider 빈 정의
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        // PasswordEncoder 설정
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        // UserDetailsService 설정
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }

    // 여러 AuthenticationProvider를 하나로 묶어 관리하는 ProviderManager(= AuthenticationManager) 빈 정의
    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        // providers 리스트에는 WebAuthnAuthenticationProvider, DaoAuthenticationProvider 등이 포함될 수 있음
        return new ProviderManager(providers);
    }

    // 보안 설정에서 제외할 리소스(정적 파일 등)를 정의하는 WebSecurityCustomizer 빈
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            // favicon.ico, js, css, webjars 등 정적 리소스 무시(보안 필터를 거치지 않음)
            web.ignoring().requestMatchers(
                    "/favicon.ico",
                    "/js/**",
                    "/css/**",
                    "/webjars/**");
        };
    }

    // Spring SecurityFilterChain을 구성
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn 전용 로그인 설정
        http.with(WebAuthnLoginConfigurer.webAuthnLogin(), (customizer)-> {
            customizer
                    .defaultSuccessUrl("/", true) // 인증 성공 시 이동할 URL(루트)
                    .failureUrl("/login")         // 인증 실패 시 이동할 URL
                    .attestationOptionsEndpoint() // Attestation Options Endpoint 설정 시작
                    .rp()                         // RP(Relying Party) 정보 설정
                    .name("WebAuthn4J-Springboot-passkey-demo") // Relying Party 이름 설정
                    .and()
                    // 등록 시 허용할 PublicKeyCredentialParameters 설정
                    .pubKeyCredParams(
                            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS1)
                    )
                    // AttestationConveyancePreference.NONE: Attestation 수집을 원치 않음 (None)
                    .attestation(AttestationConveyancePreference.NONE)
                    .extensions()
                    .uvm(true)       // User Verification Method(uvm) extension
                    .credProps(true) // Credential Properties(credProps) extension
                    .extensionProviders()
                    .and()
                    // Assertion Options Endpoint 설정
                    .assertionOptionsEndpoint()
                    .extensions()
                    .extensionProviders();
        });

//        // HTTP Header 보안 설정
//        http.headers(headers -> {
//            headers.contentSecurityPolicy(csp ->
//                    // Content-Security-Policy 설정
//                    csp.policyDirectives("default-src 'self'; frame-ancestors *; publickey-credentials-get *;")
//            );
//
//            // frameOptions: 특정 도메인에서 페이지를 iframe으로 불러올 수 있게 하려면 'disable'
//            headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable);
//        });

        // 요청별 권한 설정
        http.authorizeHttpRequests(authz -> authz
                .requestMatchers(HttpMethod.GET, "/login").permitAll()   // GET /login은 인증 없이 접근 가능
                .requestMatchers(HttpMethod.GET, "/signup").permitAll()  // GET /signup은 인증 없이 접근 가능
                .requestMatchers(HttpMethod.POST, "/signup").permitAll() // POST /signup도 인증 없이 접근 가능
                // 기타 모든 요청은 아래 ExpressionManager를 통과:
                //  '@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication) || hasAuthority('SINGLE_FACTOR_AUTHN_ALLOWED')'
                .anyRequest().access(getWebExpressionAuthorizationManager())
        );

        // 인증/인가 실패 시의 처리
        http.exceptionHandling(customizer -> {
            // 접근 거부 발생 시 /login으로 리다이렉트
            customizer.accessDeniedHandler((request, response, accessDeniedException) -> response.sendRedirect("/login"));
        });

        // 위에서 정의한 authenticationManager를 사용하도록 설정
        http.authenticationManager(authenticationManager);

        // CSRF 설정
        // WebAuthn은 자체적으로 challenge를 통한 CSRF 방어 기법을 사용하기 때문에,
        // Spring Security의 CSRF를 완전히 비활성화하지 않고 CookieCsrfTokenRepository로 설정
        // 단, /webauthn/** 요청은 CSRF 검증에서 제외
        http.csrf(customizer -> {
            customizer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
            customizer.ignoringRequestMatchers("/webauthn/**");
        });

        // 모든 설정을 마친 후 SecurityFilterChain 객체 생성
        return http.build();

    }

    // 커스텀 WebExpressionAuthorizationManager 생성
    // WebExpressionAuthorizationManager: SpEL을 사용한 권한 표현식을 처리
    private WebExpressionAuthorizationManager getWebExpressionAuthorizationManager() {
        // HttpSecurityExpressionHandler를 커스터마이징
        DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
        expressionHandler.setApplicationContext(applicationContext);
        // SpEL 표현식을 설정
        WebExpressionAuthorizationManager authorizationManager = new WebExpressionAuthorizationManager("@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication) || hasAuthority('SINGLE_FACTOR_AUTHN_ALLOWED')");
        authorizationManager.setExpressionHandler(expressionHandler);
        return authorizationManager;
    }
}
