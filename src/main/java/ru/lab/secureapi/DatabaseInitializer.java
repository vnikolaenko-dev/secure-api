package ru.lab.secureapi;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
class DatabaseInitializer implements CommandLineRunner {
    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;
    private final String initialPassword;

    DatabaseInitializer(JdbcTemplate jdbc, PasswordEncoder encoder,
                        @Value("${app.admin-password}") String initialPassword) {
        this.jdbc = jdbc;
        this.encoder = encoder;
        this.initialPassword = initialPassword;
    }

    @Override
    public void run(String... args) {
        if (initialPassword.length() < 12 || initialPassword.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException("APP_ADMIN_PASSWORD must be at least 12 characters and at most 72 UTF-8 bytes");
        }
        Integer count = jdbc.queryForObject("SELECT COUNT(*) FROM app_users WHERE username = ?", Integer.class, "admin");
        if (Integer.valueOf(0).equals(count)) {
            jdbc.update("INSERT INTO app_users(username, password_hash) VALUES (?, ?)", "admin", encoder.encode(initialPassword));
        }
    }
}
