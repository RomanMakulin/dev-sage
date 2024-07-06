package com.makulin.service;

import com.makulin.model.User;
import com.makulin.model.UserRole;
import com.makulin.repository.UserRepository;
import com.makulin.security.JwtTokenProvider;
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

import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    private final JwtTokenProvider jwtTokenProvider;

    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository,
                           AuthenticationManager authenticationManager,
                           JwtTokenProvider jwtTokenProvider,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = passwordEncoder;
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
        return userRepository.findByLogin(login) != null && userRepository.findByEmail(email) != null;
    }

    @Override
    public ResponseEntity<String> login(User userDetails) {
        try {
            User user = userRepository.findByLogin(userDetails.getLogin())
                    .orElseThrow(() -> new BadCredentialsException("Неверное имя пользователя или пароль!"));

            if (!passwordEncoder.matches(userDetails.getPassword(), user.getPassword())) {
                throw new BadCredentialsException("Неверное имя пользователя или пароль!");
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userDetails.getLogin(), userDetails.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String token = jwtTokenProvider.createToken(userDetails.getLogin());
            return ResponseEntity.ok(token);
        } catch (BadCredentialsException e) {
            log.error("Ошибка аутентификации: {}", e.getMessage());
            return ResponseEntity.status(401).body(e.getMessage());
        } catch (Exception e) {
            log.error("Ошибка сервера: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Ошибка сервера!");
        }
    }
}
