package com.thehook.ias.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class IasException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public IasException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public static IasException notFound(String resource, Object id) {
        return new IasException(
                HttpStatus.NOT_FOUND,
                "RESOURCE_NOT_FOUND",
                String.format("%s not found: %s", resource, id)
        );
    }

    public static IasException conflict(String message) {
        return new IasException(HttpStatus.CONFLICT, "CONFLICT", message);
    }

    public static IasException forbidden(String message) {
        return new IasException(HttpStatus.FORBIDDEN, "FORBIDDEN", message);
    }

    public static IasException badRequest(String message) {
        return new IasException(HttpStatus.BAD_REQUEST, "BAD_REQUEST", message);
    }

    public static IasException unauthorized(String message) {
        return new IasException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", message);
    }
}
