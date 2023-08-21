package com.green.security.config.security;

import com.green.security.config.security.model.MyUserDetails;
import com.green.security.config.security.model.UserEntity;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserDetailsMapper {
    int save(UserEntity p);
    UserEntity getByUid(String uid);

}
