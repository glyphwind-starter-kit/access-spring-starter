package dev.morvex.access.gateway;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HMAC-SHA256 over the identity headers, the time and the request target. The gateway signs
 * with it, the services verify with it, so the algorithm lives in one place.
 *
 * <p>The request method and target (path plus raw query string, see {@link #target}) are
 * part of the signature, so a captured identity cannot be replayed against another endpoint
 * or with other parameters; the time bounds replay of the identical request. The body is
 * not signed: the gateway-to-service hop is assumed to be inside the cluster network.
 */
public final class GatewaySigner {

    private static final String ALGORITHM = "HmacSHA256";
    private static final int MIN_KEY_BYTES = 32;

    private final byte[] key;

    public GatewaySigner(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("gateway secret is empty");
        }
        this.key = decode(secret);
        if (key.length < MIN_KEY_BYTES) {
            throw new IllegalArgumentException("gateway secret must be at least " + MIN_KEY_BYTES + " bytes");
        }
    }

    /** The signed request target: path plus {@code ?} and the raw query string when present. */
    public static String target(jakarta.servlet.http.HttpServletRequest request) {
        String query = request.getQueryString();
        return query == null || query.isEmpty() ? request.getRequestURI() : request.getRequestURI() + "?" + query;
    }

    public String sign(Identity identity, long epochSeconds, String method, String target) {
        return Base64.getEncoder().encodeToString(mac(message(identity, epochSeconds, method, target)));
    }

    public boolean verify(String signature, Identity identity, long epochSeconds, String method, String target) {
        if (signature == null || signature.isBlank()) {
            return false;
        }
        byte[] given;
        try {
            given = Base64.getDecoder().decode(signature);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] expected = mac(message(identity, epochSeconds, method, target));
        return MessageDigest.isEqual(expected, given);
    }

    /** What the signature covers. Permissions are joined with commas, in the given order. */
    public record Identity(String userId, String username, String sessionId, List<String> permissions) {
        public String permissionsHeader() {
            return String.join(",", permissions);
        }
    }

    private static String message(Identity identity, long epochSeconds, String method, String target) {
        return String.join(
                "\n",
                "v1",
                Long.toString(epochSeconds),
                method,
                target,
                identity.userId(),
                identity.username(),
                identity.sessionId(),
                identity.permissionsHeader());
    }

    private byte[] mac(String message) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] decode(String secret) {
        try {
            byte[] decoded = Base64.getDecoder().decode(secret);
            if (decoded.length >= MIN_KEY_BYTES) {
                return decoded;
            }
        } catch (IllegalArgumentException ignored) {
            // not base64: use the text itself
        }
        return secret.getBytes(StandardCharsets.UTF_8);
    }
}
