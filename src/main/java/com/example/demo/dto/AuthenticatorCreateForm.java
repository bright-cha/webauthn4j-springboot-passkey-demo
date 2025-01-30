package com.example.demo.dto;

import java.util.Set;

public record AuthenticatorCreateForm(
        String clientDataJSON,
        String attestationObject,
        Set<String> transports,
        String clientExtensions
) {
}
