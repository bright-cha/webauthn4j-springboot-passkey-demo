package com.example.demo.config;

import com.example.demo.dao.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.WebAuthnSecurityExpression;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.converter.jackson.WebAuthn4JSpringSecurityJSONModule;
import com.webauthn4j.springframework.security.credential.InMemoryWebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.options.*;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration // Spring 설정 클래스
public class WebSecurityBeanConfig {

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return new CustomUserDetailsService(userRepository);
    }

    // 비밀번호 인코딩을 위한 BCryptPasswordEncoder 빈
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // InMemory 기반 UserDetailsManager(테스트나 간단한 사용용)
    @Bean
    public UserDetailsManager userDetailsManager(){
        return new InMemoryUserDetailsManager();
    }

    // InMemory 기반 WebAuthnCredentialRecordManager
    // WebAuthn 등록된 Credential 데이터를 메모리에 저장하여 관리
    // 각 서비스 별로 공개 인증키를 메모리에 저장하여 관리하기 위함.
    @Bean
    public WebAuthnCredentialRecordManager webAuthnAuthenticatorManager(){
        return new InMemoryWebAuthnCredentialRecordManager();
    }

    // JSON, CBOR 직렬화/역직렬화를 위한 ObjectConverter
    @Bean
    public ObjectConverter objectConverter(){
        // JSON용 ObjectMapper 생성
        ObjectMapper jsonMapper = new ObjectMapper();
        // WebAuthn4J와 Spring Security에서 제공하는 모듈 등록
        jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
        jsonMapper.registerModule(new WebAuthn4JSpringSecurityJSONModule());

        // CBOR용 ObjectMapper 생성
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        // 두 Mapper를 종합적으로 다루는 ObjectConverter 생성 및 반환
        return new ObjectConverter(jsonMapper, cborMapper);
    }

    // WebAuthn 프로세스(인증·등록 등) 검증 기능을 제공하는 WebAuthnManager 빈
    // NonStrict 옵션: 일반적으로 구현 편의상 사용 (Strict 옵션도 있음)
    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter){
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    // SpEL(Security Expression Language)에서 WebAuthn 인증 여부를 검사하기 위한 Expression
    // 예) @webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication)
    @Bean
    public WebAuthnSecurityExpression webAuthnSecurityExpression(){
        return new WebAuthnSecurityExpression();
    }

    // Challenge를 세션에 저장하기 위한 Repository 구현체
    // WebAuthn의 Challenge는 서버와 클라이언트 간에 공유되는 nonce 같은 개념
    @Bean
    public ChallengeRepository challengeRepository() {
        return new HttpSessionChallengeRepository();
    }

    // AttestationOptionsProvider: Credential 생성 시(client 측 기기 등록) 필요한 옵션을 제공
    @Bean
    public AttestationOptionsProvider attestationOptionsProvider(RpIdProvider rpIdProvider, WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository){
        return new AttestationOptionsProviderImpl(rpIdProvider, webAuthnCredentialRecordService, challengeRepository);
    }

    // AssertionOptionsProvider: Credential 사용 시(WebAuthn 인증) 필요한 옵션을 제공
    @Bean
    public AssertionOptionsProvider assertionOptionsProvider(RpIdProvider rpIdProvider, WebAuthnCredentialRecordService webAuthnCredentialRecordService, ChallengeRepository challengeRepository) {
        return new AssertionOptionsProviderImpl(rpIdProvider, webAuthnCredentialRecordService, challengeRepository);
    }

    // Relying Party(RP) ID를 제공하는 Provider (일반적으로는 도메인과 동일)
    @Bean
    public RpIdProvider rpIdProvider(){
        return new RpIdProviderImpl();
    }

    // ServerPropertyProvider: 서버에서 WebAuthn 인증 시 필요한 파라미터(Challenge, RP ID 등) 관리
    @Bean
    public ServerPropertyProvider serverPropertyProvider(RpIdProvider rpIdProvider, ChallengeRepository challengeRepository){
        return new ServerPropertyProviderImpl(rpIdProvider, challengeRepository);
    }

    // WebAuthn 등록 요청을 검증하기 위한 Validator
    // WebAuthnManager와 ServerPropertyProvider가 필요
    @Bean
    public WebAuthnRegistrationRequestValidator webAuthnRegistrationRequestValidator(WebAuthnManager webAuthnManager, ServerPropertyProvider serverPropertyProvider){
        return new WebAuthnRegistrationRequestValidator(webAuthnManager, serverPropertyProvider);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
