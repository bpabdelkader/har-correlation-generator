package com.ngenia.harparam.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.ui.Model;
import org.springframework.util.unit.DataSize;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;

/**
 * @author bpabdelkader
 */
@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class UploadExceptionHandler {

    private static final String INDEX_VIEW = "index";

    private final String appVersion;
    private final String maxFileSize;
    private final long maxUploadBytes;

    public UploadExceptionHandler(
            @Value("${app.version:dev}") String appVersion,
            @Value("${spring.servlet.multipart.max-file-size:unknown}") String maxFileSize
    ) {
        this.appVersion = appVersion;
        this.maxFileSize = maxFileSize;
        this.maxUploadBytes = parseMaxUploadBytes(maxFileSize);
    }

    @ExceptionHandler({MaxUploadSizeExceededException.class, MultipartException.class, IllegalStateException.class})
    public String handleUploadException(Exception exception, Model model) {
        model.addAttribute("appVersion", appVersion);
        model.addAttribute("maxFileSize", maxFileSize);
        model.addAttribute("maxUploadBytes", maxUploadBytes);
        model.addAttribute("error", uploadErrorMessage(exception));
        return INDEX_VIEW;
    }

    private String uploadErrorMessage(Exception exception) {
        return isSizeLimitException(exception)
                ? "The HAR file exceeds the maximum allowed size of " + maxFileSize + "."
                : "The HAR file upload failed. Please try again with a smaller file.";
    }

    private boolean isSizeLimitException(Throwable exception) {
        Throwable current = exception;
        while (current != null) {
            if (current instanceof MaxUploadSizeExceededException) {
                return true;
            }
            String message = current.getMessage();
            if (message != null) {
                String normalized = message.toLowerCase();
                if (normalized.contains("maximum upload size")
                        || normalized.contains("size exceeded")
                        || normalized.contains("request was rejected because its size")) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
    }

    private long parseMaxUploadBytes(String configuredMaxFileSize) {
        try {
            return DataSize.parse(configuredMaxFileSize).toBytes();
        } catch (IllegalArgumentException ex) {
            return -1L;
        }
    }
}
