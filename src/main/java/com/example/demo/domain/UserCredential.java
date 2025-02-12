package com.example.demo.domain;

import com.example.demo.converter.AAGUIDConverter;
import com.example.demo.converter.COSEKeyConverter;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecord;
import jakarta.persistence.*;
import lombok.*;
import lombok.extern.slf4j.Slf4j;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
@Slf4j
public class UserCredential implements WebAuthnCredentialRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 사용자와의 연관관계 (다대일)
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // WebAuthn 등록 시 생성되는 credentialId (예: base64url 인코딩된 문자열)
    @Column(nullable = false, unique = true)
    private String credentialId;

    // 등록된 공개키 – 텍스트 형태로 저장하거나, 필요 시 바이너리 데이터로 저장
    @Column(nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    // 서명 카운터 (초기 등록 시 0 혹은 1로 시작)
    @Column(nullable = false)
    private Long counter;

    // 선택 사항: attestationObject (등록 시 클라이언트에서 전달받은 값)
    @Column(columnDefinition = "TEXT")
    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "aaguid", column = @Column(name = "aaguid", columnDefinition = "binary(16)")),
            @AttributeOverride(name = "credentialId", column = @Column(name = "attested_credential_id", columnDefinition = "BLOB")),
            @AttributeOverride(name = "coseKey", column = @Column(name = "cose_key", columnDefinition = "BLOB"))
    })

    @Converts({
            @Convert(converter = AAGUIDConverter.class, attributeName = "aaguid"),
            @Convert(converter = COSEKeyConverter.class, attributeName = "coseKey")
    })
    private AttestedCredentialData attestedCredentialData;

    // 선택 사항: clientExtensions (클라이언트 확장 정보)
    @Column(columnDefinition = "TEXT")
    private String clientExtensions;

    @Column(nullable = false)
    private boolean uvInitialized;

    @Column(nullable = false)
    private boolean backupEligible;

    @Column(nullable = false)
    private boolean backedUp;

    // transient 필드: 클라이언트 데이터는 매 요청마다 임시로 사용하므로 DB에 저장하지 않습니다.
    @Transient
    private CollectedClientData clientData;

    // ================= WebAuthnCredentialRecord 인터페이스 구현 =================

    public Object getUserPrincipal() {
        return user;
    }

    public Boolean isUvInitialized() {
        return uvInitialized;
    }

    /**
     * 백업 가능 여부 반환
     */
    public Boolean isBackupEligible() {
        return backupEligible;
    }

    /**
     * 실제 백업되었는지 여부 반환
     */
    public Boolean isBackedUp() {
        return backedUp;
    }

    /**
     * attestationObject로부터 AttestedCredentialData를 생성하는 로직이 필요합니다.
     * 현재는 별도 변환 로직이 없으므로 null을 반환합니다.
     */
    @Override
    public AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }



    @Override
    public long getCounter() {
        return counter;
    }

    @Override
    public void setCounter(long value) {
        this.counter = value;
    }

    /**
     * DB에 저장된 clientExtensions 문자열을
     * AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> 타입으로 변환하는 로직이 필요합니다.
     * 현재는 변환 로직을 구현하지 않고 null을 반환합니다.
     */
    @Override
    public AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        // TODO: clientExtensions String을 AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput>로 변환하는 로직 구현
        return null;
    }
}