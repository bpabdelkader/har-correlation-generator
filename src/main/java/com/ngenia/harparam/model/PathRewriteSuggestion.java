package com.ngenia.harparam.model;

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
) {
}
