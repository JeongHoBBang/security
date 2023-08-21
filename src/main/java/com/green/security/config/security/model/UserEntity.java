package com.green.security.config.security.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserEntity { // 데이터 베이스랑 통실할 때 쓰는것
    private Long iuser;
    private String uid;
    private String upw;
    private String name;
    private String role;
}
