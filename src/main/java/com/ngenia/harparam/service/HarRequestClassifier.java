package com.ngenia.harparam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * @author bpabdelkader
 */
@Service
class HarRequestClassifier {

    private static final Pattern IPV4_ADDRESS = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
    private static final Set<String> EXCLUDED_HOSTS = Set.of(
            "www.google.com",
            "www.googletagmanager.com",
            "www.google-analytics.com",
            "cdn.jsdelivr.net",
            "connect.facebook.net",
            "graph.facebook.com",
            "static.xx.fbcdn.net"
    );
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            "js", "css", "png", "jpg", "jpeg", "webp", "gif", "svg", "ico",
            "woff", "woff2", "ttf", "json", "mp4", "webm", "map"
    );

    Set<String> determineAllowedHostRoots(ArrayNode entries) {
        Map<String, Integer> hostCounts = new HashMap<>();

        for (JsonNode entryNode : entries) {
            JsonNode requestNode = entryNode.path("request");
            if (!(requestNode instanceof com.fasterxml.jackson.databind.node.ObjectNode request)) {
                continue;
            }

            String url = request.path("url").asText("");
            String host = extractHost(url);
            if (host.isBlank() || isKnownThirdPartyHost(host) || !isHttpOrHttps(url)) {
                continue;
            }
            if (isStaticByPath(url) || isStaticByContentType(request.path("headers"), entryNode.path("response").path("headers"))) {
                continue;
            }
            hostCounts.merge(host, 1, Integer::sum);
        }

        if (hostCounts.isEmpty()) {
            return Collections.emptySet();
        }

        String primaryHost = null;
        int max = -1;
        for (Map.Entry<String, Integer> e : hostCounts.entrySet()) {
            if (e.getValue() > max) {
                max = e.getValue();
                primaryHost = e.getKey();
            }
        }
        if (primaryHost == null) {
            return Collections.emptySet();
        }

        Set<String> roots = new HashSet<>();
        roots.add(hostRoot(primaryHost));
        return roots;
    }

    boolean isBusinessRequest(JsonNode request, JsonNode response, Set<String> allowedHostRoots) {
        String url = request.path("url").asText("");
        if (!isHttpOrHttps(url)) {
            return false;
        }

        String host = extractHost(url);
        if (host.isBlank() || isKnownThirdPartyHost(host)) {
            return false;
        }
        if (!allowedHostRoots.isEmpty() && !allowedHostRoots.contains(hostRoot(host))) {
            return false;
        }
        if (isStaticByPath(url)) {
            return false;
        }

        return !isStaticByContentType(request.path("headers"), response.path("headers"));
    }

    private boolean isKnownThirdPartyHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        if (EXCLUDED_HOSTS.contains(normalized)) {
            return true;
        }
        for (String explicit : EXCLUDED_HOSTS) {
            if (normalized.endsWith("." + explicit)) {
                return true;
            }
        }
        return false;
    }

    private boolean isStaticByPath(String url) {
        String path = extractPath(url).toLowerCase(Locale.ROOT);
        int dot = path.lastIndexOf('.');
        if (dot < 0 || dot == path.length() - 1) {
            return false;
        }
        return STATIC_EXTENSIONS.contains(path.substring(dot + 1));
    }

    private boolean isStaticByContentType(JsonNode requestHeaders, JsonNode responseHeaders) {
        String reqType = headerValue(requestHeaders, "content-type").toLowerCase(Locale.ROOT);
        String resType = headerValue(responseHeaders, "content-type").toLowerCase(Locale.ROOT);
        return isStaticContentType(reqType) || isStaticContentType(resType);
    }

    private boolean isStaticContentType(String contentType) {
        if (contentType.isBlank()) {
            return false;
        }
        return contentType.startsWith("application/javascript")
                || contentType.startsWith("text/javascript")
                || contentType.startsWith("text/css")
                || contentType.startsWith("image/")
                || contentType.startsWith("font/");
    }

    private String headerValue(JsonNode headersNode, String headerName) {
        if (!(headersNode instanceof ArrayNode headers)) {
            return "";
        }
        for (JsonNode header : headers) {
            if (header.path("name").asText("").equalsIgnoreCase(headerName)) {
                return header.path("value").asText("");
            }
        }
        return "";
    }

    private boolean isHttpOrHttps(String url) {
        String lower = Objects.toString(url, "").toLowerCase(Locale.ROOT);
        return lower.startsWith("http://") || lower.startsWith("https://");
    }

    private String extractHost(String url) {
        try {
            String host = URI.create(url).getHost();
            return host == null ? "" : host.toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    private String hostRoot(String host) {
        String normalized = Objects.toString(host, "").toLowerCase(Locale.ROOT).trim();
        if (normalized.isBlank()) {
            return normalized;
        }
        if (normalized.equals("localhost") || IPV4_ADDRESS.matcher(normalized).matches()) {
            return normalized;
        }
        String[] parts = normalized.split("\\.");
        if (parts.length < 2) {
            return normalized;
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private String extractPath(String url) {
        try {
            String path = URI.create(url).getPath();
            return (path == null || path.isBlank()) ? "/" : path;
        } catch (Exception e) {
            int query = url.indexOf('?');
            int fragment = url.indexOf('#');
            int end = url.length();
            if (query >= 0) {
                end = Math.min(end, query);
            }
            if (fragment >= 0) {
                end = Math.min(end, fragment);
            }
            String trimmed = url.substring(0, Math.max(0, end));
            int scheme = trimmed.indexOf("://");
            if (scheme >= 0) {
                int startPath = trimmed.indexOf('/', scheme + 3);
                return startPath >= 0 ? trimmed.substring(startPath) : "/";
            }
            return trimmed.isBlank() ? "/" : trimmed;
        }
    }
}
