package com.example.demo.dto;

import com.example.demo.domain.User;

public record UserDto(
        Long userId,
        String username
) {
    public static UserDto of(User user) {
        return new UserDto(
                user.getUserId(), user.getUsername()
        );
    }
}
