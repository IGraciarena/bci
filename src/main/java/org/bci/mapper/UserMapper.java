package org.bci.mapper;

import org.bci.dto.response.UserCreateResponse;
import org.bci.entities.UserEntity;
import org.bci.models.User;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import java.time.Instant;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Mapper(uses = PhoneMapper.class)
public interface UserMapper {
    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);

    default UserCreateResponse map(UserEntity user, String token) {
        return UserCreateResponse.builder()
                .id(user.getId())
                .created(user.getCreated())
                .lastLogin(Instant.now())
                .isActive(true)
                .token(token)
                .build();
    }

    User mapToModel(UserEntity user);
}