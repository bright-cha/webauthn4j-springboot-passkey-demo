package com.example.demo.dto;

public record UserCreateForm(
        String userHandle,
        String username,
        String password,
        AuthenticatorCreateForm authenticator
) {
}
