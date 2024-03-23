package com.piotrholda.spring.webflux.jwt;

import java.util.List;

import org.springframework.lang.NonNull;


import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.AllArgsConstructor;
import lombok.Builder;

@Data
@ToString
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class test {

    @NonNull
    private Long id;

    private String firstname, lastname, email /*must be unique*/, username /*must be unique*/, password; //users will have option to login with either email/username

    private List<String> roles;

    boolean isAccountExpired, isAccountLocked, isCredentialsExpired, isEnabled;

    @SuppressWarnings("null")
    public test(String firstname, String lastname, String email,  String username, String password, List<String> roles) {
        this.firstname = firstname;
        this.lastname = lastname;
        this.email = email;
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

}