package org.bci.service.impl

import org.bci.configurations.JwtUtil
import org.bci.dto.request.LoginRequest
import org.bci.dto.request.PhoneCreateRequest
import org.bci.dto.request.UserCreateRequest
import org.bci.entities.PhoneEntity
import org.bci.entities.UserEntity
import org.bci.models.Phone
import org.bci.models.User
import org.bci.repositories.UserRepository
import spock.lang.Specification
import spock.lang.Subject

import java.time.Instant

/**
 * @project ivan-graciarena-bci-challenge
 * @author ivan.graciarena
 *
 */
class UserServiceImplSpec extends Specification {

    UserRepository userRepository = Mock()
    JwtUtil jwtUtil = Mock()

    @Subject
    UserServiceImpl userService = new UserServiceImpl(userRepository, jwtUtil)

    PhoneEntity phone
    UserEntity user
    List<PhoneEntity> phoneList

    def setup() {
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
        given: "A user with some values"
        def userValues = UserCreateRequest.builder()
                .name(user.name)
                .email(user.email)
                .password(user.password)
                .phones(
                        List.of(PhoneCreateRequest.builder()
                                .number(phoneList.get(0).number)
                                .cityCode(phoneList.get(0).cityCode)
                                .countryCode(phoneList.get(0).countryCode)
                                .build())
                )
                .build()

        jwtUtil.createToken(_) >> "token"
        userRepository.save(_) >> user
        userRepository.findByEmail(_) >> Optional.ofNullable()

        when: "Service send the user request to be created"
        def result = userService.signUp(userValues)

        then: "User will be created and token will be created as well."
        with(result) {
            it.id == user.id
            it.token == 'token'
            it.lastLogin == lastLogin
            it.created == user.created
        }
    }

    def "logIn"() {
        given: "A user that is in the database"
        def loginRequest = LoginRequest.builder()
                .email(user.email)
                .password(user.password)
                .build()
        def userModel = User.builder()
                .id(user.id)
                .email(user.email)
                .name(user.name)
                .password(user.password)
                .phones(List.of(
                        Phone.builder()
                                .id(phone.id)
                                .number(phone.number)
                                .countryCode(phone.countryCode)
                                .cityCode(phone.cityCode)
                                .build()
                ))
                .build()

        userService.getUserByEmail(user.email) >> userModel
        userRepository.findByEmail(_) >> Optional.of(user)
        jwtUtil.createToken(userModel) >> 'token'

        when:"The user tries to log-in"
        def result = userService.logIn(loginRequest)

        then:"The user will be logged in"
        with(result) {
            id == user.id
            name == user.name
            email == user.email
            password == user.password
            lastLogin == lastLogin
            created == user.created
            with(phones.get(0)) {
                number == phone.number
//                countryCode = phone.countryCode
                cityCode == phone.cityCode
            }
        }
    }
}
