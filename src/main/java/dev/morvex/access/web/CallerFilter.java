package dev.morvex.access.web;

import dev.morvex.access.AccessProperties;
import dev.morvex.access.Caller;
import dev.morvex.access.gateway.GatewaySigner;
import dev.morvex.access.gateway.IdentityHeaders;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Turns the gateway's identity headers into a {@link Caller} on the request. Headers without
 * a valid signature are ignored (the caller stays anonymous) and logged: they are either a
 * misconfiguration or someone trying to impersonate a user from inside the network.
 */
public class CallerFilter extends OncePerRequestFilter {

    public static final String ATTRIBUTE = Caller.class.getName();

    private static final Logger log = LoggerFactory.getLogger(CallerFilter.class);

    private final GatewaySigner signer;
    private final AccessProperties.Gateway settings;
    private final Clock clock;

    public CallerFilter(GatewaySigner signer, AccessProperties.Gateway settings, Clock clock) {
        this.signer = signer;
        this.settings = settings;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        request.setAttribute(ATTRIBUTE, resolve(request));
        chain.doFilter(request, response);
    }

    private Caller resolve(HttpServletRequest request) {
        String userId = request.getHeader(IdentityHeaders.USER);
        if (userId == null || userId.isBlank()) {
            return Caller.anonymous();
        }
        if (duplicated(request)) {
            log.warn("{} {}: repeated identity headers, ignored", request.getMethod(), request.getRequestURI());
            return Caller.anonymous();
        }
        String username = header(request, IdentityHeaders.USERNAME);
        String sessionId = header(request, IdentityHeaders.SESSION);
        List<String> permissions = permissions(request.getHeader(IdentityHeaders.PERMISSIONS));
        if (!settings.required()) {
            return Caller.of(userId, username, sessionId, permissions);
        }
        GatewaySigner.Identity identity = new GatewaySigner.Identity(userId, username, sessionId, permissions);
        Long time = parseTime(request.getHeader(IdentityHeaders.TIME));
        if (time == null || Math.abs(clock.instant().getEpochSecond() - time) > settings.maxClockSkew().toSeconds()) {
            log.warn("{} {}: identity headers with stale or missing time, ignored", request.getMethod(), request.getRequestURI());
            return Caller.anonymous();
        }
        boolean valid = signer.verify(
                request.getHeader(IdentityHeaders.SIGNATURE), identity, time, request.getMethod(), request.getRequestURI());
        if (!valid) {
            log.warn("{} {}: identity headers with an invalid signature, ignored", request.getMethod(), request.getRequestURI());
            return Caller.anonymous();
        }
        return Caller.of(userId, username, sessionId, permissions);
    }

    /** Two values for one identity header means someone appended their own: never pick one. */
    private static boolean duplicated(HttpServletRequest request) {
        for (String name : IdentityHeaders.ALL) {
            Enumeration<String> values = request.getHeaders(name);
            if (values != null && values.hasMoreElements()) {
                values.nextElement();
                if (values.hasMoreElements()) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? "" : value;
    }

    private static List<String> permissions(String header) {
        if (header == null || header.isBlank()) {
            return List.of();
        }
        return Arrays.stream(header.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    private static Long parseTime(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static Caller callerOf(HttpServletRequest request) {
        Object found = request.getAttribute(ATTRIBUTE);
        return found instanceof Caller caller ? caller : Caller.anonymous();
    }
}
