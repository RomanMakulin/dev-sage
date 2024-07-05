package com.makulin.service;

import com.makulin.model.User;
import com.makulin.model.UserRole;
import com.makulin.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Регистрация нового пользователя
     *
     * @param userDetails данные о новом пользователе
     * @return новый объект пользователя
     */
    @Override
    public User registration(User userDetails) {
        User user = new User();
        try {
            user.setEmail(userDetails.getEmail());
            user.setPassword(userDetails.getPassword());
            user.setName(userDetails.getName());
            user.setLogin(userDetails.getLogin());
            user.setUserRole(UserRole.USER);

            log.info("Registration successful: {}", user);
            return userRepository.save(userDetails);
        } catch (NullPointerException e) {
            throw new NullPointerException("Регистрация пользователя не удалась. " +
                    "Есть пустые поля: " + e.getMessage());
        }
    }
}
