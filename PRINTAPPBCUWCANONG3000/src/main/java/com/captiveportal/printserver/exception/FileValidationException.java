package com.captiveportal.printserver.exception;

/**
 * Thrown when an uploaded file fails any validation layer.
 *
 * <p>This is an application-checked exception; it is caught by the controller
 * and translated into an HTTP 400 Bad Request with a safe, non-leaking message.
 */
public class FileValidationException extends Exception {

    public FileValidationException(String message) {
        super(message);
    }

    public FileValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
