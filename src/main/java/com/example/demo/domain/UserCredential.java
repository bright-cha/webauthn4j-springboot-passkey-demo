package com.example.demo.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 사용자와의 연관관계 (다대일)
    @ManyToOne(fetch = FetchType.LAZY)
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
    private Long signCount;

    // 선택 사항: attestationObject (등록 시 클라이언트에서 전달받은 값)
    @Column(columnDefinition = "TEXT")
    private String attestationObject;

    // 선택 사항: clientExtensions (클라이언트 확장 정보)
    @Column(columnDefinition = "TEXT")
    private String clientExtensions;

    public void setSignCount(long newCounter) {
        this.signCount = newCounter;
    }
}