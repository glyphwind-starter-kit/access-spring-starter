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
    @RequestMapping("/api/v1/mixed")
    @PublicEndpoint
    static class Mixed {
        @GetMapping("/open")
        Map<String, String> open() {
            return Map.of("ok", "open");
        }

        @GetMapping("/protected")
        @RequiresPermission("orders:admin")
        Map<String, String> guarded() {
            return Map.of("ok", "guarded");
        }
    }

    @RestController
    @RequestMapping("/api/v1/locked")
    @RequiresPermission("orders:admin")
    static class Locked {
        @GetMapping("/any")
        @Authenticated
        Map<String, String> any() {
            return Map.of("ok", "any");
        }

        @GetMapping("/strict")
        Map<String, String> strict() {
            return Map.of("ok", "strict");
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
