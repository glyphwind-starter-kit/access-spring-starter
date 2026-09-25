package dev.morvex.access;

import java.util.List;

/** Thrown by {@link Caller#require} and mapped to 403 by the starter. */
public class AccessDeniedException extends RuntimeException {

    private final List<String> required;

    public AccessDeniedException(String... required) {
        super("permission " + String.join(" | ", required) + " is required");
        this.required = List.of(required);
    }

    public List<String> required() {
        return required;
    }
}
