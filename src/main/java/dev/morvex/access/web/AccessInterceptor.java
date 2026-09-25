package dev.morvex.access.web;

import dev.morvex.access.AccessProperties;
import dev.morvex.access.Authenticated;
import dev.morvex.access.Caller;
import dev.morvex.access.PublicEndpoint;
import dev.morvex.access.RequiresPermission;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.annotation.Annotation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Enforces the access annotations. Deny by default: a handler under the configured path
 * patterns with no annotation requires a signed-in caller (or is open, when
 * {@code access.default-policy=public}).
 */
public class AccessInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AccessInterceptor.class);

    private final AccessProperties.DefaultPolicy defaultPolicy;

    public AccessInterceptor(AccessProperties.DefaultPolicy defaultPolicy) {
        this.defaultPolicy = defaultPolicy;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        if (!(handler instanceof HandlerMethod method)) {
            return true;
        }
        if (find(method, PublicEndpoint.class) != null) {
            return true;
        }
        Caller caller = CallerFilter.callerOf(request);
        RequiresPermission required = find(method, RequiresPermission.class);
        if (required == null && find(method, Authenticated.class) == null
                && defaultPolicy == AccessProperties.DefaultPolicy.PUBLIC) {
            return true;
        }
        if (!caller.authenticated()) {
            ApiErrors.write(response, HttpStatus.UNAUTHORIZED, "not_authenticated", "sign in first", null);
            return false;
        }
        if (required == null) {
            return true;
        }
        for (String permission : required.value()) {
            if (caller.can(permission)) {
                return true;
            }
        }
        String wanted = String.join(" | ", required.value());
        log.info("{} {} refused for {}: {} is missing", request.getMethod(), request.getRequestURI(), caller.username(), wanted);
        ApiErrors.write(response, HttpStatus.FORBIDDEN, "permission_required", "permission " + wanted + " is required", wanted);
        return false;
    }

    private static <A extends Annotation> A find(HandlerMethod method, Class<A> type) {
        A found = method.getMethodAnnotation(type);
        return found != null ? found : method.getBeanType().getAnnotation(type);
    }
}
