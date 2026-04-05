package com.ngenia.harparam.model;

import java.util.Map;

/**
 * @author bpabdelkader
 */
public record RewrittenRequest(
        int index,
        String kind,
        String name,
        String method,
        String startedDateTime,
        Integer sourceIndex,
        String sourceName,
        String sourceMethod,
        String sourceUrl,
        String sourceBody,
        String sourceVariableName,
        String sourceVariableValue,
        String sourceExtractionType,
        String sourceHeaderName,
        String sourceHeaderValue,
        String sourceResponseBody,
        Map<String, String> sourceVariables,
        String originalUrl,
        String rewrittenUrl,
        Map<String, String> originalHeaders,
        Map<String, String> rewrittenHeaders,
        String originalBody,
        String rewrittenBody
) {
}
