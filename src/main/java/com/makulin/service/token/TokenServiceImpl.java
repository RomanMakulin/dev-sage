package com.makulin.service.token;

import com.makulin.model.Token;
import com.makulin.model.User;
import com.makulin.repository.TokenRepository;
import com.makulin.security.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class TokenServiceImpl implements TokenService{

    private final TokenRepository tokenRepository;

    private final JwtTokenProvider jwtTokenProvider;

    @Value("${jwt.expiration}")
    private long validityInMilliseconds;

    public TokenServiceImpl(TokenRepository tokenRepository,
                            JwtTokenProvider jwtTokenProvider) {
        this.tokenRepository = tokenRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public Token createToken(User user) {
        String accessToken = jwtTokenProvider.createToken(user.getLogin());
        String refreshToken = UUID.randomUUID().toString();
        ZonedDateTime expiryDate = ZonedDateTime.now().plusSeconds(validityInMilliseconds / 1000); // Преобразуем миллисекунды в секунды

        Token token = new Token();
        token.setUser(user);
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setExpiryDate(expiryDate);

        return tokenRepository.save(token);
    }

    @Override
    public Optional<Token> findByAccessToken(String accessToken) {
        return tokenRepository.findByAccessToken(accessToken);
    }

    @Override
    public Optional<Token> findByRefreshToken(String refreshToken) {
        return tokenRepository.findByRefreshToken(refreshToken);
    }

    @Override
    public void deleteToken(Token token) {
        tokenRepository.delete(token);
    }

}
