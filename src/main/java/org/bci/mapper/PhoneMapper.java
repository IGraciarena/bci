package org.bci.mapper;

import org.bci.dto.request.PhoneCreateRequest;
import org.bci.dto.response.PhoneResponse;
import org.bci.entities.PhoneEntity;
import org.bci.models.Phone;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

import java.util.List;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Mapper
public interface PhoneMapper {
    PhoneMapper INSTANCE = Mappers.getMapper(PhoneMapper.class);

    PhoneEntity map(PhoneCreateRequest phone);

    List<PhoneEntity> map(List<PhoneCreateRequest> phones);

    Phone map(PhoneEntity phone);
    PhoneResponse map(Phone phone);
    List<PhoneResponse> mapToResponse(List<Phone> phone);
}
