package com.green.security.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.green.security.config.security.model.EntryPointErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException authException) throws IOException, ServletException {
        ObjectMapper objectMapper = new ObjectMapper(); // Json <-> 객체 로 컨버팅
        log.info("[commence] 인증 실패로 response.sendError 발생");

        EntryPointErrorResponse msg = new EntryPointErrorResponse();
        msg.setMsg("인증이 실패하였습니다.");

        res.setStatus(401);
        res.setContentType(MediaType.APPLICATION_JSON_VALUE); // 보내는 타입확인
        res.setCharacterEncoding("UTF-8");
        res.getWriter().write(objectMapper.writeValueAsString(msg));
    }
}
