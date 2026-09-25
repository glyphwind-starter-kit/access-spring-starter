package dev.morvex.access;

import java.util.Map;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootConfiguration
@EnableAutoConfiguration
public class TestApp {

    @RestController
    @RequestMapping("/api/v1")
    static class Endpoints {

        @GetMapping("/open")
        @PublicEndpoint
        Map<String, String> open() {
            return Map.of("ok", "open");
        }

        @GetMapping("/me")
        @Authenticated
        Map<String, Object> me(Caller caller) {
            return Map.of("user", caller.username(), "permissions", caller.permissions());
        }

        @GetMapping("/orders")
        @RequiresPermission({"orders:read", "orders:admin"})
        Map<String, String> orders() {
            return Map.of("ok", "orders");
        }

        @GetMapping("/plain")
        Map<String, String> plain() {
            return Map.of("ok", "plain");
        }

        @GetMapping("/manual")
        @Authenticated
        Map<String, String> manual(Caller caller) {
            caller.require("orders:delete");
            return Map.of("ok", "manual");
        }
    }

    @RestController
    static class Outside {
        @GetMapping("/healthz")
        Map<String, String> health() {
            return Map.of("ok", "health");
        }
    }
}
