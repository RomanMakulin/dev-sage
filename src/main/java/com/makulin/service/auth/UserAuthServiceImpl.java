package com.makulin.service.auth;

import com.makulin.model.Token;
import com.makulin.model.User;
import com.makulin.model.UserRole;
import com.makulin.repository.UserRepository;
import com.makulin.security.JwtTokenProvider;
import com.makulin.service.token.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.ZonedDateTime;
import java.util.Optional;

@Service
public class UserAuthServiceImpl implements UserAuthService {

    private static final Logger log = LoggerFactory.getLogger(UserAuthServiceImpl.class);

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final JwtTokenProvider jwtTokenProvider;

    private final PasswordEncoder passwordEncoder;

    private final TokenService tokenService;

    public UserAuthServiceImpl(UserRepository userRepository,
                               AuthenticationManager authenticationManager,
                               JwtTokenProvider jwtTokenProvider,
                               PasswordEncoder passwordEncoder, TokenService tokenService) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
    }

    /**
     * Регистрация нового пользователя
     *
     * @param userDetails данные о новом пользователе
     * @return новый объект пользователя
     */
    @Override
    public User registration(User userDetails) {

        if (checkRegistration(userDetails.getEmail(), userDetails.getLogin())) {
            throw new IllegalArgumentException("User already exists");
        }

        User user = new User();
        try {
            user.setEmail(userDetails.getEmail());
            user.setPassword(passwordEncoder.encode(userDetails.getPassword()));
            user.setName(userDetails.getName());
            user.setLogin(userDetails.getLogin());
            user.setUserRole(UserRole.USER);

            log.info("Registration successful: {}", user);
            return userRepository.save(user);
        } catch (NullPointerException e) {
            throw new NullPointerException("Регистрация пользователя не удалась. " +
                    "Есть пустые поля: " + e.getMessage());
        }
    }

    boolean checkRegistration(String email, String login) {
        return userRepository.findByLogin(login).isPresent() && userRepository.findByEmail(email).isPresent();
    }

    @Override
    public ResponseEntity<Token> login(User userDetails) {
        try {
            User user = checkLogin(userDetails); // проверка пользователя на логин и пароль

            Authentication authentication = getAuthentication(userDetails);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            Token token = tokenService.createToken(user);
            return ResponseEntity.ok(token);
        } catch (BadCredentialsException e) {
            log.error("Ошибка аутентификации: {}", e.getMessage());
            return ResponseEntity.status(401).body(null);
        } catch (Exception e) {
            log.error("Ошибка сервера: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    @Override
    public ResponseEntity<Token> refresh(String refreshToken) {
        Optional<Token> optionalToken = tokenService.findByRefreshToken(refreshToken);
        if (optionalToken.isEmpty()) {
            return ResponseEntity.status(403).body(null); // Неверный refresh token
        }

        Token token = optionalToken.get();
        if (token.getExpiryDate().isBefore(ZonedDateTime.now())) {
            return ResponseEntity.status(403).body(null); // Refresh token истек
        }

        User user = token.getUser();
        tokenService.deleteToken(token); // Удаляем старый токен
        Token newToken = tokenService.createToken(user); // Создаем новый токен

        return ResponseEntity.ok(newToken);
    }

    public Authentication getAuthentication(User userDetails) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userDetails.getLogin(), userDetails.getPassword())
        );
    }

    public User checkLogin(User userDetails) {
        User user = userRepository.findByLogin(userDetails.getLogin())
                .orElseThrow(() -> new BadCredentialsException("Пользователь не найден!"));

        if (!passwordEncoder.matches(userDetails.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Неверное имя пользователя или пароль!");
        }
        return user;
    }
}
