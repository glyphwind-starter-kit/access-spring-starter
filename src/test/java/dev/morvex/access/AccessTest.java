package dev.morvex.access;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.morvex.access.gateway.GatewaySigner;
import dev.morvex.access.gateway.IdentityHeaders;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest(
        classes = TestApp.class,
        properties = "access.gateway.secret=0123456789abcdef0123456789abcdef-test-secret")
@AutoConfigureMockMvc
@Import(AccessTest.FixedClock.class)
class AccessTest {

    static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");
    static final GatewaySigner SIGNER = new GatewaySigner("0123456789abcdef0123456789abcdef-test-secret");

    @TestConfiguration
    static class FixedClock {
        @Bean
        Clock accessClock() {
            return Clock.fixed(NOW, ZoneOffset.UTC);
        }
    }

    @Autowired
    MockMvc mvc;

    @Test
    void publicEndpointNeedsNothing() throws Exception {
        mvc.perform(get("/api/v1/open")).andExpect(status().isOk());
    }

    @Test
    void pathsOutsideThePatternsAreNotGuarded() throws Exception {
        mvc.perform(get("/healthz")).andExpect(status().isOk());
    }

    @Test
    void unannotatedHandlerRequiresSignInByDefault() throws Exception {
        mvc.perform(get("/api/v1/plain"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("not_authenticated"));
        mvc.perform(signed(get("/api/v1/plain"), "orders:read")).andExpect(status().isOk());
    }

    @Test
    void anonymousIsRefusedWithStandardBody() throws Exception {
        mvc.perform(get("/api/v1/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.code").value("not_authenticated"));
    }

    @Test
    void signedIdentityIsResolvedIntoCaller() throws Exception {
        mvc.perform(signed(get("/api/v1/me"), "orders:read", "orders:write"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("alice"))
                .andExpect(jsonPath("$.permissions", containsInAnyOrder("orders:read", "orders:write")));
    }

    @Test
    void unsignedIdentityHeadersAreIgnored() throws Exception {
        mvc.perform(get("/api/v1/me")
                        .header(IdentityHeaders.USER, "u1")
                        .header(IdentityHeaders.USERNAME, "mallory")
                        .header(IdentityHeaders.PERMISSIONS, "orders:admin"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tamperedPermissionsBreakTheSignature() throws Exception {
        long now = NOW.getEpochSecond();
        GatewaySigner.Identity signedFor = new GatewaySigner.Identity("u1", "alice", "s1", List.of("orders:none"));
        mvc.perform(get("/api/v1/orders")
                        .header(IdentityHeaders.USER, "u1")
                        .header(IdentityHeaders.USERNAME, "alice")
                        .header(IdentityHeaders.SESSION, "s1")
                        .header(IdentityHeaders.PERMISSIONS, "orders:none,orders:admin")
                        .header(IdentityHeaders.TIME, now)
                        .header(IdentityHeaders.SIGNATURE, SIGNER.sign(signedFor, now, "GET", "/api/v1/orders")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void repeatedIdentityHeadersAreIgnored() throws Exception {
        MockHttpServletRequestBuilder request = signed(get("/api/v1/orders"), "orders:admin");
        request.header(IdentityHeaders.PERMISSIONS, "orders:admin");
        mvc.perform(request).andExpect(status().isUnauthorized());
    }

    @Test
    void signatureIsBoundToTheRequestPath() throws Exception {
        long now = NOW.getEpochSecond();
        GatewaySigner.Identity identity = new GatewaySigner.Identity("u1", "alice", "s1", List.of("orders:read"));
        String forOtherPath = SIGNER.sign(identity, now, "GET", "/api/v1/me");
        mvc.perform(get("/api/v1/orders")
                        .header(IdentityHeaders.USER, "u1")
                        .header(IdentityHeaders.USERNAME, "alice")
                        .header(IdentityHeaders.SESSION, "s1")
                        .header(IdentityHeaders.PERMISSIONS, "orders:read")
                        .header(IdentityHeaders.TIME, now)
                        .header(IdentityHeaders.SIGNATURE, forOtherPath))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signatureIsBoundToTheQueryString() throws Exception {
        long now = NOW.getEpochSecond();
        GatewaySigner.Identity identity = new GatewaySigner.Identity("u1", "alice", "s1", List.of("orders:read"));
        String forId1 = SIGNER.sign(identity, now, "GET", "/api/v1/orders?id=1");
        mvc.perform(get("/api/v1/orders?id=2")
                        .header(IdentityHeaders.USER, "u1")
                        .header(IdentityHeaders.USERNAME, "alice")
                        .header(IdentityHeaders.SESSION, "s1")
                        .header(IdentityHeaders.PERMISSIONS, "orders:read")
                        .header(IdentityHeaders.TIME, now)
                        .header(IdentityHeaders.SIGNATURE, forId1))
                .andExpect(status().isUnauthorized());
        mvc.perform(signed(get("/api/v1/orders?id=1"), "orders:read")).andExpect(status().isOk());
    }

    @Test
    void methodRuleWinsOverClassRule() throws Exception {
        // class is @PublicEndpoint, method demands a permission
        mvc.perform(get("/api/v1/mixed/protected")).andExpect(status().isUnauthorized());
        mvc.perform(signed(get("/api/v1/mixed/protected"), "orders:read")).andExpect(status().isForbidden());
        mvc.perform(signed(get("/api/v1/mixed/protected"), "orders:admin")).andExpect(status().isOk());
        mvc.perform(get("/api/v1/mixed/open")).andExpect(status().isOk());
        // class demands a permission, method is only @Authenticated
        mvc.perform(get("/api/v1/locked/any")).andExpect(status().isUnauthorized());
        mvc.perform(signed(get("/api/v1/locked/any"), "nothing:special")).andExpect(status().isOk());
        mvc.perform(signed(get("/api/v1/locked/strict"), "nothing:special")).andExpect(status().isForbidden());
    }

    @Test
    void staleSignatureIsRejected() throws Exception {
        long old = NOW.minusSeconds(120).getEpochSecond();
        mvc.perform(signedAt(get("/api/v1/me"), old, "orders:read")).andExpect(status().isUnauthorized());
    }

    @Test
    void permissionAnyOfIsEnforced() throws Exception {
        mvc.perform(signed(get("/api/v1/orders"), "orders:admin")).andExpect(status().isOk());
        mvc.perform(signed(get("/api/v1/orders"), "orders:write"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("permission_required"))
                .andExpect(jsonPath("$.params.permission").value("orders:read | orders:admin"));
    }

    @Test
    void manualRequireMapsToTheSameBody() throws Exception {
        mvc.perform(signed(get("/api/v1/manual"), "orders:read"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("permission_required"))
                .andExpect(jsonPath("$.params.permission").value("orders:delete"));
        mvc.perform(signed(get("/api/v1/manual"), "orders:delete")).andExpect(status().isOk());
    }

    static MockHttpServletRequestBuilder signed(MockHttpServletRequestBuilder request, String... permissions) {
        return signedAt(request, NOW.getEpochSecond(), permissions);
    }

    static MockHttpServletRequestBuilder signedAt(
            MockHttpServletRequestBuilder request, long time, String... permissions) {
        var built = request.buildRequest(null);
        String path = built.getQueryString() == null ? built.getRequestURI() : built.getRequestURI() + "?" + built.getQueryString();
        String method = built.getMethod();
        GatewaySigner.Identity identity = new GatewaySigner.Identity("u1", "alice", "s1", List.of(permissions));
        return request.header(IdentityHeaders.USER, identity.userId())
                .header(IdentityHeaders.USERNAME, identity.username())
                .header(IdentityHeaders.SESSION, identity.sessionId())
                .header(IdentityHeaders.PERMISSIONS, identity.permissionsHeader())
                .header(IdentityHeaders.TIME, time)
                .header(IdentityHeaders.SIGNATURE, SIGNER.sign(identity, time, method, path));
    }
}
