package com.example.demo.service;

import com.example.demo.dao.UserCredentialRepository;
import com.example.demo.dao.UserRepository;
import com.example.demo.domain.User;
import com.example.demo.domain.UserCredential;
import com.example.demo.dto.UserCreateForm;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final UserCredentialRepository userCredentialRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final WebAuthnRegistrationRequestValidator registrationRequestValidator;

    public void save(HttpServletRequest request, UserCreateForm userCreateForm) {
        String encPassword = bCryptPasswordEncoder.encode(userCreateForm.password());

        User user = User.builder()
                .username(userCreateForm.username())
                .password(encPassword)
                .build();

        userRepository.save(user);

        WebAuthnRegistrationRequestValidationResponse registrationResponse;
        registrationResponse = registrationRequestValidator.validate(
                request,
                userCreateForm.authenticator().clientDataJSON(),
                userCreateForm.authenticator().attestationObject(),
                userCreateForm.authenticator().transports(),
                userCreateForm.authenticator().clientExtensions()
        );

        // registrationResponse를 이용해 attestedCredentialData에서 credentialId와 공개키를 추출
        byte[] rawCredentialId = Objects.requireNonNull(registrationResponse.getAttestationObject()
                        .getAuthenticatorData()
                        .getAttestedCredentialData())
                .getCredentialId();

        String credentialId = Base64.getUrlEncoder().withoutPadding().encodeToString(rawCredentialId);
        // 공개키는 라이브러리의 헬퍼 메서드 등을 사용하여 추출
        String publicKey = extractPublicKeyFromAttestation(registrationResponse.getAttestationObject());

        UserCredential credential = UserCredential.builder()
                .user(user)
                .credentialId(credentialId) // 폼의 clientDataJSON이 아니라 검증된 credentialId 사용
                .publicKey(publicKey)
                .signCount(registrationResponse.getAttestationObject().getAuthenticatorData().getSignCount())
                .attestationObject(userCreateForm.authenticator().attestationObject()) // 또는 registrationResponse로부터 얻은 원본 데이터를 저장
                .clientExtensions(userCreateForm.authenticator().clientExtensions())
                .build();

        userCredentialRepository.save(credential);

        log.info("회원가입 완료: username={}", userCreateForm.username());
    }

    private String extractPublicKeyFromAttestation(AttestationObject attestationObject) {
        AttestedCredentialData attestedCredentialData = attestationObject
                .getAuthenticatorData()
                .getAttestedCredentialData();
        if (attestedCredentialData == null) {
            throw new IllegalStateException("Attested Credential Data가 존재하지 않습니다.");
        }

        COSEKey coseKey = attestedCredentialData.getCOSEKey();
        if (coseKey == null) {
            throw new IllegalStateException("Credential Public Key가 존재하지 않습니다.");
        }

        // COSEKey에서 PublicKey 객체를 가져온 후, getEncoded()로 byte 배열을 얻는다.
        PublicKey publicKey = coseKey.getPublicKey();
        if(publicKey == null){
            throw new IllegalStateException("COSEKey의 PublicKey가 null 입니다.");
        }

        byte[] publicKeyBytes = publicKey.getEncoded();
        // Base64 URL 인코딩 (padding 없이)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes);
    }


}
