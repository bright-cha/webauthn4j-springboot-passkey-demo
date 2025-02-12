package com.example.demo.service;

import com.example.demo.dao.UserCredentialRepository;
import com.example.demo.dao.UserRepository;
import com.example.demo.domain.User;
import com.example.demo.domain.UserCredential;
import com.example.demo.dto.UserCreateForm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import com.webauthn4j.springframework.security.converter.Base64UrlStringToAttestationObjectConverter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
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
    private final Base64UrlStringToAttestationObjectConverter base64UrlStringToAttestationObjectConverter;

    public void save(HttpServletRequest request, UserCreateForm userCreateForm) throws JsonProcessingException {
        String encPassword = bCryptPasswordEncoder.encode(userCreateForm.password());

        byte[] cborBytes = Base64.getUrlDecoder().decode(userCreateForm.authenticator().attestationObject());
        log.info("디코딩된 attestationObject bytes: {}", Arrays.toString(cborBytes));

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

        AttestationObject parsedAttestationObject = base64UrlStringToAttestationObjectConverter.convert(userCreateForm.authenticator().attestationObject());
        assert parsedAttestationObject != null;
        AttestedCredentialData attestedCredentialData = parsedAttestationObject
                .getAuthenticatorData()
                .getAttestedCredentialData();


        UserCredential credential = UserCredential.builder()
                .user(user)
                .credentialId(credentialId) // 폼의 clientDataJSON이 아니라 검증된 credentialId 사용
                .publicKey(publicKey)
                .counter(registrationResponse.getAttestationObject().getAuthenticatorData().getSignCount())
                .attestedCredentialData(attestedCredentialData) // 또는 registrationResponse로부터 얻은 원본 데이터를 저장
                .clientExtensions(userCreateForm.authenticator().clientExtensions())
                .uvInitialized(true)
                .backedUp(false)
                .backupEligible(true)
                .build();

        userCredentialRepository.save(credential);

        log.info("회원가입 완료: username={}", userCreateForm.username());
    }

    private String extractPublicKeyFromAttestation(AttestationObject attestationObject) throws JsonProcessingException {
        AttestedCredentialData attestedCredentialData = attestationObject
                .getAuthenticatorData()
                .getAttestedCredentialData();
        if (attestedCredentialData == null) {
            throw new IllegalStateException("Attested Credential Data가 존재하지 않습니다.");
        }

        COSEKey coseKey = attestedCredentialData.getCOSEKey();
        if (coseKey == null) {
            throw new IllegalStateException("❌ Credential Public Key가 존재하지 않습니다.");
        }

        log.info("✅ 회원가입 과정에서 추출된 COSEKey: {}", coseKey.toString());

//        // COSEKey에서 PublicKey 객체를 가져온 후, getEncoded()로 byte 배열을 얻는다.
//        PublicKey publicKey = coseKey.getPublicKey();
//        if(publicKey == null){
//            throw new IllegalStateException("COSEKey의 PublicKey가 null 입니다.");
//        }

//        byte[] publicKeyBytes = publicKey.getEncoded();
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        byte[] coseKeyBytes = cborMapper.writeValueAsBytes(coseKey);


        // Base64 URL 인코딩 (padding 없이)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(coseKeyBytes);
    }


}
