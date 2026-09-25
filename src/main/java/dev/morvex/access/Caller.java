package dev.morvex.access;

import java.util.List;
import java.util.Set;

/**
 * Who is calling, as established by the API gateway. Present only when the gateway signed
 * the identity headers; {@link #anonymous()} otherwise.
 *
 * @param userId      stable user id (UUID as text)
 * @param username    login name, for logs and audit
 * @param sessionId   session the request belongs to; lets a service refuse a session that
 *                    was revoked between two calls if it chooses to double-check
 * @param permissions effective permissions, {@code resource:action}
 */
public record Caller(String userId, String username, String sessionId, Set<String> permissions) {

    private static final Caller ANONYMOUS = new Caller(null, null, null, Set.of());

    public static Caller anonymous() {
        return ANONYMOUS;
    }

    public static Caller of(String userId, String username, String sessionId, List<String> permissions) {
        return new Caller(userId, username, sessionId, Set.copyOf(permissions));
    }

    public boolean authenticated() {
        return userId != null;
    }

    public boolean can(String permission) {
        return permissions.contains(permission);
    }

    /** Throws {@link AccessDeniedException} unless one of the permissions is granted. */
    public void require(String... anyOf) {
        for (String permission : anyOf) {
            if (can(permission)) {
                return;
            }
        }
        throw new AccessDeniedException(anyOf);
    }
}
