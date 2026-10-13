package com.captiveportal.printserver.exception;

/**
 * Thrown when the print subsystem cannot deliver a job to the OS printer.
 */
public class PrintException extends Exception {

    public PrintException(String message) {
        super(message);
    }

    public PrintException(String message, Throwable cause) {
        super(message, cause);
    }
}
