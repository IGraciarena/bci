package org.bci.utils;

import org.bci.dto.request.LoginRequest;
import org.bci.dto.request.PhoneCreateRequest;
import org.bci.dto.request.UserCreateRequest;
import org.bci.dto.response.LoginResponse;
import org.bci.dto.response.PhoneResponse;
import org.bci.dto.response.UserCreateResponse;
import org.bci.entities.PhoneEntity;
import org.bci.entities.UserEntity;
import org.bci.models.Phone;
import org.bci.models.User;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
public final class EntityUtils {
    private EntityUtils() {
    }

    public static final PhoneEntity PHONE_ENTITY_STUB = PhoneEntity.builder()
            .id(UUID.randomUUID())
            .number(1156323991L)
            .countryCode("MDQ")
            .cityCode(7600)
            .build();
    public static final List<PhoneEntity> PHONE_ENTITY_LIST_STUB = List.of(PHONE_ENTITY_STUB);

    public static final UserEntity USER_ENTITY_STUB = UserEntity.builder()
            .id(UUID.randomUUID())
            .email("mail.test@gmail.com")
            .name("Jhon")
            .password("Somesecret11")
            .created(Instant.now())
            .phones(PHONE_ENTITY_LIST_STUB)
            .build();

    public static final Phone PHONE_MODEL_STUB = Phone.builder()
            .id(PHONE_ENTITY_STUB.getId())
            .number(PHONE_ENTITY_STUB.getNumber())
            .cityCode(PHONE_ENTITY_STUB.getCityCode())
            .countryCode(PHONE_ENTITY_STUB.getCountryCode())
            .build();
    public static final List<Phone> PHONE_MODEL_LIST_STUB = List.of(PHONE_MODEL_STUB);
    public static final User USER_MODEL_STUB = User.builder()
            .id(USER_ENTITY_STUB.getId())
            .name(USER_ENTITY_STUB.getName())
            .created(USER_ENTITY_STUB.getCreated())
            .email(USER_ENTITY_STUB.getEmail())
            .password(USER_ENTITY_STUB.getPassword())
            .phones(PHONE_MODEL_LIST_STUB)
            .build();

    public static final PhoneCreateRequest PHONE_CREATE_REQUEST_STUB = PhoneCreateRequest.builder()
            .number(PHONE_ENTITY_STUB.getNumber())
            .cityCode(PHONE_ENTITY_STUB.getCityCode())
            .countryCode(PHONE_ENTITY_STUB.getCountryCode())
            .build();
    public static final List<PhoneCreateRequest> PHONE_CREATE_REQUEST_LIST_STUB = List
            .of(PHONE_CREATE_REQUEST_STUB);
    public static final UserCreateRequest USER_CREATE_REQUEST_STUB = UserCreateRequest.builder()
            .email(USER_ENTITY_STUB.getEmail())
            .name(USER_ENTITY_STUB.getName())
            .password(USER_ENTITY_STUB.getPassword())
            .phones(PHONE_CREATE_REQUEST_LIST_STUB)
            .build();
    public static final UserCreateResponse USER_CREATE_RESPONSE_STUB = UserCreateResponse.builder()
            .id(USER_ENTITY_STUB.getId())
            .created(USER_ENTITY_STUB.getCreated())
            .isActive(true)
            .token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqaG9uZG9lQGdtYWlsLmNvbSIsImlkIjoiZjk2NWE5NTgtYzk0M" +
                    "i00NjM4LWE1ODItOTgyNmM0OTViNzRjIiwibmFtZSI6Ikpob24iLCJwYXNzd29yZCI6IiQyYSQxMCR6eDJZM1RQO" +
                    "VBUcDJRY3VuMkRkMjllOHkuNG9XeURkUk1MUWJjdmx0dk5obHFoWGtSTDVTTyIsImV4cCI6MTkxNzI2MzQ0NH0.K" +
                    "PFE4aGl90ftNBTTfxEHDzDc7r-oDu-Z0Z5WwwmXvU4")
            .lastLogin(Instant.now())
            .build();
    public static final PhoneResponse PHONE_RESPONSE_STUB = PhoneResponse.builder()
            .number(PHONE_ENTITY_STUB.getNumber())
            .cityCode(PHONE_ENTITY_STUB.getCityCode())
            .countryCode(PHONE_ENTITY_STUB.getCountryCode())
            .build();
    public static final List<PhoneResponse> PHONE_RESPONSE_LIST_STUB = List.of(PHONE_RESPONSE_STUB);
    public static final LoginResponse LOG_IN_RESPONSE_STUB = LoginResponse.builder()
            .id(USER_ENTITY_STUB.getId())
            .created(USER_ENTITY_STUB.getCreated())
            .password(USER_ENTITY_STUB.getPassword())
            .name(USER_ENTITY_STUB.getName())
            .isActive(true)
            .token("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqaG9uZG9lQGdtYWlsLmNvbSIsImlkIjoiZjk2NWE5NTgtYzk0M" +
                    "i00NjM4LWE1ODItOTgyNmM0OTViNzRjIiwibmFtZSI6Ikpob24iLCJwYXNzd29yZCI6IiQyYSQxMCR6eDJZM1RQO" +
                    "VBUcDJRY3VuMkRkMjllOHkuNG9XeURkUk1MUWJjdmx0dk5obHFoWGtSTDVTTyIsImV4cCI6MTkxNzI2MzQ0NH0.K" +
                    "PFE4aGl90ftNBTTfxEHDzDc7r-oDu-Z0Z5WwwmXvU4")
            .lastLogin(Instant.now())
            .phones(PHONE_RESPONSE_LIST_STUB)
            .build();
    public static final LoginRequest LOG_IN_REQUEST_STUB = LoginRequest.builder()
            .email(USER_ENTITY_STUB.getEmail())
            .password(USER_ENTITY_STUB.getPassword())
            .build();
}
