/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.demo.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import jakarta.persistence.AttributeConverter;

import java.util.Map;

public class ClientExtensionsConverter implements AttributeConverter<Map<String, RegistrationExtensionClientOutput>, String> {

    private final JsonConverter jsonConverter;

    public ClientExtensionsConverter(ObjectConverter objectConverter) {
        this.jsonConverter = objectConverter.getJsonConverter();
    }

    @Override
    public String convertToDatabaseColumn(Map<String, RegistrationExtensionClientOutput> attribute) {
        return jsonConverter.writeValueAsString(attribute);
    }

    @Override
    public Map<String, RegistrationExtensionClientOutput> convertToEntityAttribute(String dbData) {
        return jsonConverter.readValue(dbData, new TypeReference<Map<String, RegistrationExtensionClientOutput>>() {
        });
    }
}
