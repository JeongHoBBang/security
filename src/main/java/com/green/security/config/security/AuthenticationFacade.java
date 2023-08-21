package com.green.security.config.security;

import com.green.security.config.security.model.MyUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;


@Component
// 서비스 딴에서 PK값을 가저오고 싶은경우..
public class AuthenticationFacade {
    public MyUserDetails getLoginUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        MyUserDetails userDetails = (MyUserDetails) auth.getPrincipal();
        return userDetails;
    }

    public Long getLoginUserPk() {
        return getLoginUser().getIuser();
    }
}
