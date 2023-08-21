package com.green.security.config.security.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Builder
public class MyUserDetails implements UserDetails { // jw토큰에 들어갈 내용
    private Long iuser;
    private String uid;
    private String upw;
    private String name;
    // 누구누구님 반갑습니다와 프로필을 같이 보여주고 싶을 때 셀렉을 프로필 사진까지 가져오도록 추가 해주면 됨
    
    @Builder.Default
    private List<String> roles = new ArrayList<>();


    @Override // 권한을 리턴하는 부분 // 이름은 맘대로 줘도됨..
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        //return this.roles.stream().map(item -> new SimpleGrantedAuthority(item)).collect(Collectors.toList());
    } // stream().map은 리스트의 크기와 같은 리스트를 만들고 다른 내용으로 채우고 싶을 때

    @Override
    public String getPassword() { return this.upw; }

    @Override
    public String getUsername() { return this.uid; }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
