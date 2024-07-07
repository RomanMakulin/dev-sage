package com.makulin.service.token;

import com.makulin.model.Token;
import com.makulin.model.User;

import java.util.Optional;

public interface TokenService {
    Token createToken(User user);
    Optional<Token> findByAccessToken(String accessToken);
    Optional<Token> findByRefreshToken(String refreshToken);
    void deleteToken(Token token);
}
