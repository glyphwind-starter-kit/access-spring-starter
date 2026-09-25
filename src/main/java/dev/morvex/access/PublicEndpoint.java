package dev.morvex.access;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The handler is reachable without a signed identity (health, login). Under the default
 * deny policy every {@code /api/**} handler must carry one of the three access annotations.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface PublicEndpoint {}
