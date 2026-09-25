package dev.morvex.access.web;

import dev.morvex.access.AccessDeniedException;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Maps {@link AccessDeniedException} (from {@code Caller.require}) to the standard 403 body. */
@RestControllerAdvice
public class AccessDeniedAdvice {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> denied(AccessDeniedException e) {
        String wanted = String.join(" | ", e.required());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of(
                        "status", 403,
                        "code", "permission_required",
                        "error", "permission " + wanted + " is required",
                        "params", Map.of("permission", wanted)));
    }
}
