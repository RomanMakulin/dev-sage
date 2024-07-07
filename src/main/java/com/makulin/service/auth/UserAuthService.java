package com.makulin.service.auth;

import com.makulin.model.Token;
import com.makulin.model.User;
import org.springframework.http.ResponseEntity;

public interface UserAuthService {
    User registration(User userDetails);
    ResponseEntity<Token> login(User userDetails);
    ResponseEntity<Token> refresh(String refreshToken);
}
