package ru.lab.secureapi;

import java.net.URI;
import java.net.http.*;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import tools.jackson.databind.ObjectMapper;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
    "spring.datasource.password=test-db-only",
    "app.jwt-secret=test-only-secret-at-least-thirty-two-bytes-long",
    "app.admin-password=Test-Password-2026!"
})
class SecureApiApplicationTests {
    @LocalServerPort int port;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtEncoder encoder;
    private final HttpClient client = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    HttpResponse<String> request(String method, String path, String body, String token) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
            .header("Content-Type", "application/json");
        if (token != null) builder.header("Authorization", "Bearer " + token);
        return client.send(builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    String login() throws Exception {
        var response = request("POST", "/auth/login", "{\"username\":\"admin\",\"password\":\"Test-Password-2026!\"}", null);
        assertThat(response.statusCode()).isEqualTo(200);
        return mapper.readTree(response.body()).get("accessToken").asString();
    }

    @Test void anonymousAndForgedTokensAreRejected() throws Exception {
        assertThat(request("GET", "/api/data", null, null).statusCode()).isEqualTo(401);
        assertThat(request("POST", "/api/data", "{\"content\":\"x\"}", null).statusCode()).isEqualTo(401);
        assertThat(request("GET", "/api/data", null, "fake.jwt.token").statusCode()).isEqualTo(401);
        String token = login();
        String forged = (token.charAt(0) == 'a' ? "b" : "a") + token.substring(1);
        assertThat(request("GET", "/api/data", null, forged).statusCode()).isEqualTo(401);
    }

    @Test void incorrectPasswordAndSqlInjectionAreRejected() throws Exception {
        for (String username : new String[]{"admin", "' OR '1'='1"}) {
            String body = mapper.writeValueAsString(java.util.Map.of("username", username, "password", "wrong"));
            assertThat(request("POST", "/auth/login", body, null).statusCode()).isEqualTo(401);
        }
    }

    @Test void createEscapesXssAndStoresSqlPayloadAsText() throws Exception {
        String token = login();
        String payload = "<script>alert('x')</script>'); DROP TABLE app_users; --";
        var created = request("POST", "/api/data", mapper.writeValueAsString(java.util.Map.of("content", payload)), token);
        assertThat(created.statusCode()).isEqualTo(201);
        assertThat(created.body()).contains("&lt;script&gt;").doesNotContain("<script>");
        var data = request("GET", "/api/data", null, token);
        assertThat(data.statusCode()).isEqualTo(200);
        assertThat(data.body()).contains("&lt;script&gt;");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM app_users", Integer.class)).isEqualTo(1);
    }

    @Test void passwordIsHashedAndInvalidInputRejected() throws Exception {
        String hash = jdbc.queryForObject("SELECT password_hash FROM app_users WHERE username = ?", String.class, "admin");
        assertThat(hash).startsWith("$2").isNotEqualTo("Test-Password-2026!");
        assertThat(passwords.matches("Test-Password-2026!", hash)).isTrue();
        assertThat(request("POST", "/api/data", "{\"content\":\" \"}", login()).statusCode()).isEqualTo(400);
        assertThat(request("POST", "/auth/login", "{broken", null).statusCode()).isEqualTo(400);
    }

    @Test void expiredAndWrongIssuerTokensRejectedAndDataIsPrivate() throws Exception {
        for (String issuer : new String[]{"secure-api", "wrong-issuer"}) {
            Instant now = Instant.now();
            var claims = JwtClaimsSet.builder().issuer(issuer).subject("admin")
                .issuedAt(now.minusSeconds(600)).expiresAt(issuer.equals("secure-api") ? now.minusSeconds(300) : now.plusSeconds(900)).build();
            String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
            assertThat(request("GET", "/api/data", null, token).statusCode()).isEqualTo(401);
        }
        jdbc.update("INSERT INTO app_users(username,password_hash) VALUES (?,?)", "other", passwords.encode("Other-Password-2026!"));
        jdbc.update("INSERT INTO posts(owner,content) VALUES (?,?)", "other", "private-other-post");
        assertThat(request("GET", "/api/data", null, login()).body()).doesNotContain("private-other-post");
        jdbc.update("DELETE FROM posts WHERE owner = ?", "other");
        jdbc.update("DELETE FROM app_users WHERE username = ?", "other");
    }
}
