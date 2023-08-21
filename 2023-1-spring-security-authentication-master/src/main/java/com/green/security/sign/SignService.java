package com.green.security.sign;

import com.green.security.CommonRes;
import com.green.security.config.security.JwtTokenProvider;
import com.green.security.config.security.UserDetailsMapper;
import com.green.security.config.security.model.MyUserDetails;
import com.green.security.config.security.model.UserEntity;
import com.green.security.sign.model.SignInResultDto;
import com.green.security.sign.model.SignUpResultDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class SignService {
    private final UserDetailsMapper MAPPER;
    private final JwtTokenProvider JWT_PROVIDER;
    private final PasswordEncoder PW_ENCODER;

    public SignUpResultDto signUp(String id, String pw, String nm, String role) {
        log.info("[getSignUpResult] signDataHandler로 회원 정보 요청");
        UserEntity user = UserEntity.builder()
                .uid(id)
                .upw(PW_ENCODER.encode(pw))
                .name(nm)
                .role(String.format("ROLE_%s", role))
                .build();
        int result = MAPPER.save(user);
        SignUpResultDto dto = new SignUpResultDto();

        if(result == 1) {
            log.info("[getSignUpResult] 정상 처리 완료");
            setSuccessResult(dto);
        } else {
            log.info("[getSignUpResult] 실패 처리 완료");
            setFileResult(dto);
        }
        return dto;
    }

    public SignInResultDto signIn(String id, String password) throws RuntimeException {
        log.info("[getSignInResult] signDataHandler로 회원 정보 요청");
        UserEntity user = MAPPER.getByUid(id);

        log.info("[getSignInResult] id: {}", id);

        log.info("[getSignInResult] 패스워드 비교");
        if(!PW_ENCODER.matches(password, user.getUpw())) {
            throw new RuntimeException("비밀번호 다름");
        }
        log.info("[getSignInResult] 패스워드 일치");


        log.info("[getSignInResult] SignInResultDto 객체 생성");
        String token = JWT_PROVIDER.generateJwtToken(String.valueOf(user.getUid()), Collections.singletonList(user.getRole()));
        SignInResultDto dto = SignInResultDto.builder()
                                .token(token)
                                .build();

        log.info("[getSignInResult] SignInResultDto 객체 값 주입");
        setSuccessResult(dto);
        return dto;
    }

    private void setSuccessResult(SignUpResultDto result) {
        result.setSuccess(true);
        result.setCode(CommonRes.SUCCESS.getCode());
        result.setMsg(CommonRes.SUCCESS.getMsg());
    }

    private void setFileResult(SignUpResultDto result) {
        result.setSuccess(false);
        result.setCode(CommonRes.FAIL.getCode());
        result.setMsg(CommonRes.FAIL.getMsg());
    }
}

