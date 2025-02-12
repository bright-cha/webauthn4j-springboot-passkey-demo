package com.example.demo.config;

import com.example.demo.dao.UserCredentialRepository;
import com.example.demo.domain.UserCredential;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecord;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.exception.CredentialIdNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.List;

@Service
@Slf4j
@Transactional
public class CustomWebAuthnCredentialRecordService implements WebAuthnCredentialRecordService {

    private UserCredentialRepository userCredentialRepository;

    public CustomWebAuthnCredentialRecordService(UserCredentialRepository userCredentialRepository) {
        this.userCredentialRepository = userCredentialRepository;
    }

    @Override
    public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {
        UserCredential userCredential = findUserCredentialByCredentialId(credentialId);
        userCredential.setCounter(counter);
    }

    @Override
    public WebAuthnCredentialRecord loadCredentialRecordByCredentialId(byte[] credentialId) throws CredentialIdNotFoundException {
        return findUserCredentialByCredentialId(credentialId);
    }

    @Override
    public List<WebAuthnCredentialRecord> loadCredentialRecordsByUserPrincipal(Object principal) {
        return List.of();
    }

    private UserCredential findUserCredentialByCredentialId(byte[] credentialId) {
        String strCredentialId = Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId);
        log.info("검색하려는 credentialId: {}", strCredentialId);

        return userCredentialRepository.findByCredentialId(strCredentialId)
                .orElseThrow(() -> new CredentialIdNotFoundException(strCredentialId));
    }
}