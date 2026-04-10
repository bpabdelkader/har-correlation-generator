package com.ngenia.harparam.model;

import java.io.Serial;
import java.io.Serializable;

/**
 * @author bpabdelkader
 */
public record PathRewriteSuggestion(
        int requestIndex,
        String requestName,
        String originalUrl,
        String currentUrl,
        String proposedUrl,
        String variableName,
        String value
) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
}
