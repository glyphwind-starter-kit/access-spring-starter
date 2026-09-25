package dev.morvex.access;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * {@code access.*} settings.
 *
 * @param pathPatterns   which handlers the access rules apply to
 * @param defaultPolicy  what an un-annotated handler under the patterns requires
 * @param gateway        signature settings; the secret is shared with the gateway (Vault)
 */
@ConfigurationProperties("access")
public record AccessProperties(
        @DefaultValue("/api/**") List<String> pathPatterns,
        @DefaultValue("authenticated") DefaultPolicy defaultPolicy,
        @DefaultValue Gateway gateway) {

    public enum DefaultPolicy {
        /** Un-annotated handler: caller must be signed in. Safe default. */
        AUTHENTICATED,
        /** Un-annotated handler: open. Only for services without any protected API. */
        PUBLIC
    }

    /**
     * @param secret        HMAC key, base64 or plain text, at least 32 bytes; required unless
     *                      {@code required=false}
     * @param required      when false identity headers are trusted unsigned: only for local
     *                      runs without a gateway, never in a deployed environment
     * @param maxClockSkew  how old a signature may be; bounds replay of a captured request
     */
    public record Gateway(
            String secret,
            @DefaultValue("true") boolean required,
            @DefaultValue("60s") Duration maxClockSkew) {}
}
