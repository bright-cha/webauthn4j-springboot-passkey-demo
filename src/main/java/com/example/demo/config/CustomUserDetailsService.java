package com.example.demo.config;

import com.example.demo.dao.UserRepository;
import com.example.demo.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        // DB에서 사용자 조회 (없으면 UsernameNotFoundException 발생)
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));
        // DaoAuthenticationProvider는 여기서 반환된 UserDetails 객체의 password와 권한 정보를 비교함.
        // 일반 로그인 사용자의 경우 SINGLE_FACTOR_AUTHN_ALLOWED 권한을 부여합니다.
        return user;
    }
}
