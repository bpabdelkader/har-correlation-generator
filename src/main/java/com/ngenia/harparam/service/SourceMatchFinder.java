package com.ngenia.harparam.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * @author bpabdelkader
 */
@Service
class SourceMatchFinder {

    SourceSearchIndex newIndex() {
        return new SourceSearchIndex();
    }

    ResponseSnapshot snapshotFromResponse(JsonNode response, RequestRef requestRef) {
        String bodyText = response.path("content").path("text").asText("");
        Map<String, String> headers = new LinkedHashMap<>();

        JsonNode headersNode = response.path("headers");
        if (headersNode.isArray()) {
            for (JsonNode header : headersNode) {
                String headerName = header.path("name").asText("");
                String headerValue = header.path("value").asText("");
                if (!headerValue.isBlank()) {
                    headers.put(headerName, headerValue);
                }
            }
        }
        return new ResponseSnapshot(bodyText, headers, requestRef);
    }

    final class SourceSearchIndex {
        private final List<IndexedResponseSnapshot> snapshots = new ArrayList<>();
        private final Map<SearchKey, SourceMatch> namedMatchCache = new HashMap<>();
        private final Map<String, SourceMatch> headerMatchCache = new HashMap<>();
        private final Map<String, SourceMatch> bodyMatchCache = new HashMap<>();

        void add(ResponseSnapshot snapshot) {
            if (snapshot == null) {
                return;
            }
            snapshots.add(new IndexedResponseSnapshot(snapshot, decode(snapshot.bodyText())));
            namedMatchCache.clear();
            headerMatchCache.clear();
            bodyMatchCache.clear();
        }

        SourceMatch findFirstSourceMatch(String parameterName, String value) {
            if (value == null || value.isBlank()) {
                return null;
            }

            String normalizedParameterName = Objects.toString(parameterName, "").trim();
            if (!normalizedParameterName.isBlank()) {
                SearchKey key = new SearchKey(normalizedParameterName, value);
                if (namedMatchCache.containsKey(key)) {
                    return namedMatchCache.get(key);
                }
                SourceMatch namedMatch = findNamedBodyMatch(normalizedParameterName, value);
                namedMatchCache.put(key, namedMatch);
                if (namedMatch != null) {
                    return namedMatch;
                }
            }

            if (headerMatchCache.containsKey(value)) {
                SourceMatch cached = headerMatchCache.get(value);
                if (cached != null) {
                    return cached;
                }
            } else {
                SourceMatch headerMatch = findHeaderMatch(normalizedParameterName, value);
                headerMatchCache.put(value, headerMatch);
                if (headerMatch != null) {
                    return headerMatch;
                }
            }

            if (bodyMatchCache.containsKey(value)) {
                return bodyMatchCache.get(value);
            }
            SourceMatch bodyMatch = findBodyValueMatch(normalizedParameterName, value);
            bodyMatchCache.put(value, bodyMatch);
            return bodyMatch;
        }

        private SourceMatch findNamedBodyMatch(String parameterName, String value) {
            for (IndexedResponseSnapshot indexedSnapshot : snapshots) {
                String body = indexedSnapshot.snapshot().bodyText();
                if (containsNamedOccurrence(body, parameterName, value)
                        || containsNamedOccurrence(indexedSnapshot.decodedBodyText(), parameterName, value)) {
                    return new SourceMatch(indexedSnapshot.snapshot().requestRef(), "BODY", null, null, body, parameterName);
                }
            }
            return null;
        }

        private SourceMatch findHeaderMatch(String parameterName, String value) {
            for (IndexedResponseSnapshot indexedSnapshot : snapshots) {
                for (Map.Entry<String, String> header : indexedSnapshot.snapshot().headers().entrySet()) {
                    String headerValue = header.getValue();
                    if (headerValue != null && headerValue.contains(value)) {
                        return new SourceMatch(
                                indexedSnapshot.snapshot().requestRef(),
                                "HEADER",
                                header.getKey(),
                                headerValue,
                                indexedSnapshot.snapshot().bodyText(),
                                parameterName
                        );
                    }
                }
            }
            return null;
        }

        private SourceMatch findBodyValueMatch(String parameterName, String value) {
            for (IndexedResponseSnapshot indexedSnapshot : snapshots) {
                String body = indexedSnapshot.snapshot().bodyText();
                if ((body != null && body.contains(value))
                        || (!indexedSnapshot.decodedBodyText().equals(body) && indexedSnapshot.decodedBodyText().contains(value))) {
                    return new SourceMatch(indexedSnapshot.snapshot().requestRef(), "BODY", null, null, body, parameterName);
                }
            }
            return null;
        }
    }

    private boolean containsNamedOccurrence(String text, String parameterName, String value) {
        if (text == null || text.isBlank() || parameterName == null || parameterName.isBlank() || value == null || value.isBlank()) {
            return false;
        }

        if (text.contains(parameterName + "=" + value)
                || text.contains(parameterName + "\\u003d" + value)
                || matchesJsonField(text, parameterName, value, false)
                || matchesJsonField(text, parameterName, value, true)) {
            return true;
        }

        String decoded = decode(text);
        return !decoded.equals(text)
                && (decoded.contains(parameterName + "=" + value)
                || matchesJsonField(decoded, parameterName, value, false));
    }

    private boolean matchesJsonField(String text, String parameterName, String value, boolean escapedQuotes) {
        if (text == null || text.isBlank()) {
            return false;
        }
        String quote = escapedQuotes ? "\\\"" : "\"";
        String keyToken = quote + parameterName + quote;
        int from = 0;
        while (true) {
            int keyStart = text.indexOf(keyToken, from);
            if (keyStart < 0) {
                return false;
            }
            int cursor = skipJsonWhitespace(text, keyStart + keyToken.length());
            if (cursor >= text.length() || text.charAt(cursor) != ':') {
                from = keyStart + 1;
                continue;
            }
            cursor = skipJsonWhitespace(text, cursor + 1);
            if (cursor >= text.length()) {
                return false;
            }
            if (text.startsWith(quote, cursor)) {
                int valueStart = cursor + quote.length();
                int valueEnd = valueStart + value.length();
                if (valueEnd + quote.length() <= text.length()
                        && text.regionMatches(valueStart, value, 0, value.length())
                        && text.startsWith(quote, valueEnd)) {
                    return true;
                }
            } else if (text.regionMatches(cursor, value, 0, value.length())) {
                return true;
            }
            from = keyStart + 1;
        }
    }

    private int skipJsonWhitespace(String text, int index) {
        int cursor = index;
        while (cursor < text.length()) {
            char current = text.charAt(cursor);
            if (current != ' ' && current != '\t' && current != '\r' && current != '\n') {
                break;
            }
            cursor++;
        }
        return cursor;
    }

    private String decode(String value) {
        if (value == null || (value.indexOf('%') < 0 && value.indexOf('+') < 0)) {
            return value;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private record IndexedResponseSnapshot(
            ResponseSnapshot snapshot,
            String decodedBodyText
    ) {
    }

    private record SearchKey(
            String parameterName,
            String value
    ) {
    }
}
