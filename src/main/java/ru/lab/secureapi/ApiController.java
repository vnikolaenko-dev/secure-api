package ru.lab.secureapi;

import java.time.Instant;
import java.util.List;
import java.nio.charset.StandardCharsets;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;

@RestController
class ApiController {
    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;
    private final JwtEncoder jwtEncoder;
    private final String dummyHash;

    ApiController(JdbcTemplate jdbc, PasswordEncoder encoder, JwtEncoder jwtEncoder) {
        this.jdbc = jdbc;
        this.encoder = encoder;
        this.jwtEncoder = jwtEncoder;
        this.dummyHash = encoder.encode(java.util.UUID.randomUUID().toString());
    }

    record Login(@NotBlank @Size(max = 64) String username, @NotBlank @Size(max = 72) String password) {}
    record Token(String accessToken, String tokenType, long expiresIn) {}
    record NewPost(@NotBlank @Size(max = 2000) String content) {}
    record Post(long id, String owner, String content) {}

    @PostMapping("/auth/login")
    Token login(@Valid @RequestBody Login login) {
        if (login.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password too long");
        }
        List<String> hashes = jdbc.query("SELECT password_hash FROM app_users WHERE username = ?",
            (rs, row) -> rs.getString(1), login.username());
        boolean matches = encoder.matches(login.password(), hashes.isEmpty() ? dummyHash : hashes.getFirst());
        if (!matches || hashes.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer("secure-api").subject(login.username())
            .issuedAt(now).expiresAt(now.plusSeconds(900)).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(
            JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        return new Token(token, "Bearer", 900);
    }

    @GetMapping("/api/data")
    List<Post> data(@AuthenticationPrincipal Jwt jwt) {
        return jdbc.query("SELECT id, owner, content FROM posts WHERE owner = ? ORDER BY id",
            (rs, row) -> new Post(rs.getLong("id"), HtmlUtils.htmlEscape(rs.getString("owner")),
                HtmlUtils.htmlEscape(rs.getString("content"))), jwt.getSubject());
    }

    @PostMapping("/api/data")
    @ResponseStatus(HttpStatus.CREATED)
    Post create(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody NewPost post) {
        Long id = jdbc.queryForObject(
            "SELECT id FROM FINAL TABLE (INSERT INTO posts(owner, content) VALUES (?, ?))",
            Long.class, jwt.getSubject(), post.content());
        return new Post(java.util.Objects.requireNonNull(id), HtmlUtils.htmlEscape(jwt.getSubject()), HtmlUtils.htmlEscape(post.content()));
    }
}
