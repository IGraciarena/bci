package org.bci.controllers

import com.fasterxml.jackson.databind.ObjectMapper
import org.bci.dto.request.LoginRequest
import org.bci.dto.request.PhoneCreateRequest
import org.bci.dto.request.UserCreateRequest
import org.bci.dto.response.LoginResponse
import org.bci.dto.response.PhoneResponse
import org.bci.dto.response.UserCreateResponse
import org.bci.entities.PhoneEntity
import org.bci.entities.UserEntity
import org.bci.service.UserService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import spock.lang.Specification

import java.time.Instant

/**
 * @project Default (Template) Project
 * @author ivan.graciarena
 *
 */
@WebMvcTest(controllers = [AuthController])
class AuthControllerSpec extends Specification {

    @Autowired
    protected MockMvc mockMvc

    @Autowired
    UserService userService

    @Autowired
    ObjectMapper objectMapper

    PhoneEntity phone
    UserEntity user
    List<PhoneEntity> phoneList

    def "setup"() {
        phone = new PhoneEntity()
        phone.with {
            id = UUID.randomUUID()
            number = 1156323991L
            countryCode = "MDQ"
            cityCode = 7600
        }
        phoneList = List.of(phone)
        user = new UserEntity()
        user.with {
            id = UUID.randomUUID()
            email = "mail.test@gmail.com"
            name = "Jhon"
            password = "Somesecret11"
            created = Instant.now()
            phones = phoneList
        }
    }

    def "signUp"() {
        given: "A user that wants to be created to access for the first time"
        def request = UserCreateRequest.builder()
                .email(user.email)
                .name(user.name)
                .password(user.password)
                .phones(List.of(PhoneCreateRequest.builder()
                        .number(phone.number)
                        .countryCode(phone.countryCode)
                        .cityCode(phone.cityCode)
                        .build()))
                .build();
        def expected = UserCreateResponse.builder()
                .id(user.id)
                .created(user.created)
                .isActive(true)
                .token("token")
                .lastLogin(user.created)
                .build()

        userService.signUp(_) >> expected

        when: "The user hit post signUp endpoint"
        def response =
                mockMvc
                        .perform(MockMvcRequestBuilders.post("/api/sign-up")
                                .content(objectMapper.writeValueAsString(request))
                                .contentType(MediaType.APPLICATION_JSON_VALUE)).andReturn().response

        then: "A User will be created and store in the Database with the new JWT Token"
        response.status == HttpStatus.CREATED.value()

        with(objectMapper.readValue(response.contentAsString, UserCreateResponse)) {
            it.id == expected.id
            it.created == expected.created
            it.lastLogin == expected.created
            it.token == expected.token
            it.isActive() == expected.isActive()
        }
    }

    def "logIn"() {
        given: "A user that's already in the database"
        def request = LoginRequest.builder()
                .email(user.email)
                .password(user.password)
                .build()

        def expected = LoginResponse.builder()
                .id(user.id)
                .created(user.created)
                .lastLogin(user.created)
                .token("token")
                .name(user.name)
                .email(user.email)
                .password(user.password)
                .phones(List.of(
                        PhoneResponse.builder()
                                .number(phone.number)
                                .cityCode(phone.cityCode)
                                .countryCode(phone.countryCode).build()))
                .build()

        userService.logIn(request) >> expected
        when: "User was found in the database and can login"
        def response =
                mockMvc
                        .perform(MockMvcRequestBuilders.post("/api/log-in")
                                .content(objectMapper.writeValueAsString(request))
                                .contentType(MediaType.APPLICATION_JSON_VALUE)
                                .header("Authorization", "Bearer token")).andReturn().response

        then: "User was login successfully and jwt token was created."
        with(objectMapper.readValue(response.contentAsString, LoginResponse.class)) {
            id == user.id
            created == user.created
            lastLogin == user.created
            token == 'token'
            name == user.name
            email == user.email
            password == user.password
            with(phones) {
                get(0).getNumber() == phone.number
                get(0).getCityCode() == phone.cityCode
                get(0).getCountryCode() == phone.countryCode
            }
        }
    }
}