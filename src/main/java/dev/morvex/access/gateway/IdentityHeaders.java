package dev.morvex.access.gateway;

/** Header names the gateway sets and the services read. Shared by both sides. */
public final class IdentityHeaders {
    public static final String USER = "X-Auth-User";
    public static final String USERNAME = "X-Auth-Username";
    public static final String SESSION = "X-Auth-Session";
    public static final String PERMISSIONS = "X-Auth-Permissions";
    public static final String TIME = "X-Auth-Time";
    public static final String SIGNATURE = "X-Auth-Signature";

    public static final String[] ALL = {USER, USERNAME, SESSION, PERMISSIONS, TIME, SIGNATURE};

    private IdentityHeaders() {}
}
