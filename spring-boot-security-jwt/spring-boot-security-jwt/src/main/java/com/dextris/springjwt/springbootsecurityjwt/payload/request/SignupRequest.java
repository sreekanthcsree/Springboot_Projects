package com.dextris.springjwt.springbootsecurityjwt.payload.request;

import jakarta.annotation.Nonnull;
import jakarta.persistence.Column;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jdk.jfr.Name;
import org.springframework.lang.NonNull;

import java.util.Set;

public class SignupRequest {

    @NotBlank
    @Size(min = 3,max = 30)

    @NonNull
    private String username;
    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    private Set<String>role;

    @NotBlank
    @Size(min = 5,max = 50)
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<String> getRole() {
        return role;
    }

    public void setRole(Set<String> role) {
        this.role = role;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
