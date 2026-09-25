package dev.morvex.access.web;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/** The error body every service answers with: {@code {status, code, error, params}}. */
final class ApiErrors {

    private ApiErrors() {}

    static void write(HttpServletResponse response, HttpStatus status, String code, String reason, String permission)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        String params = permission == null ? "{}" : "{\"permission\":\"" + escape(permission) + "\"}";
        response.getWriter()
                .write("{\"status\":" + status.value() + ",\"code\":\"" + code + "\",\"error\":\"" + escape(reason)
                        + "\",\"params\":" + params + "}");
    }

    private static String escape(String text) {
        return text.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
