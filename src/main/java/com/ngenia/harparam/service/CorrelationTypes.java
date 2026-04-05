package com.ngenia.harparam.service;

import java.util.Map;

/**
 * @author bpabdelkader
 */
record RequestRef(
        int index,
        String name,
        String method,
        String url,
        String body
) {
}

/**
 * @author bpabdelkader
 */
record SourceMatch(
        RequestRef requestRef,
        String extractionType,
        String headerName,
        String headerValue,
        String responseBody,
        String parameterName
) {
}

/**
 * @author bpabdelkader
 */
record ResponseSnapshot(
        String bodyText,
        Map<String, String> headers,
        RequestRef requestRef
) {
}
