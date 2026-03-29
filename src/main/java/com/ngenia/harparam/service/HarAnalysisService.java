package com.ngenia.harparam.service;

import com.ngenia.harparam.model.AnalysisResult;
import com.ngenia.harparam.model.RewrittenRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class HarAnalysisService {

    private static final Pattern VAR_SAFE = Pattern.compile("[^a-zA-Z0-9_]");
    private static final Pattern VAR_TOKEN = Pattern.compile("\\$\\{([^}]+)}");
    private static final Pattern JSON_STRING_FIELD_PREFIX = Pattern.compile("\"([^\"]{1,80})\"\\s*:\\s*\"");
    private static final String[] URL_PARAM_SEPARATORS = {"?", "&", "\\u0026", "&amp;", "%3F", "%26"};
    private static final String[] URL_PARAM_ASSIGNMENTS = {"=", "\\u003d", "%3D"};
    private static final String[] URL_PARAM_SUFFIXES = {"&", "\\u0026", "&amp;", "#", "\\u0023", "%26", "%23"};
    private static final Set<String> EXCLUDED_HOSTS = Set.of(
            "www.google.com",
            "www.googletagmanager.com",
            "www.google-analytics.com",
            "connect.facebook.net",
            "graph.facebook.com",
            "static.xx.fbcdn.net"
    );
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "map"
    );
    private static final Set<String> EXCLUDED_DYNAMIC_PARAM_NAMES = Set.of(
            "redirecturl",
            "returnurl",
            "targeturl",
            "redirect",
            "return",
            "url",
            "uri",
            "next",
            "destination",
            "callback",
            "callbackurl"
    );
    private final ObjectMapper objectMapper;

    public HarAnalysisService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public AnalysisResult analyze(MultipartFile harFile) throws IOException {
        JsonNode parsedRoot = objectMapper.readTree(harFile.getInputStream());
        if (!(parsedRoot instanceof ObjectNode originalRoot)) {
            throw new IllegalArgumentException("Invalid HAR structure: JSON root is not an object.");
        }
        ObjectNode modifiedRoot = originalRoot.deepCopy();

        JsonNode originalEntriesNode = originalRoot.path("log").path("entries");
        JsonNode modifiedEntriesNode = modifiedRoot.path("log").path("entries");
        if (!(originalEntriesNode instanceof ArrayNode originalEntries) || !(modifiedEntriesNode instanceof ArrayNode modifiedEntries)) {
            throw new IllegalArgumentException("Invalid HAR structure: log.entries not found.");
        }

        Map<String, String> variables = new LinkedHashMap<>();
        Map<String, String> valueToVariable = new LinkedHashMap<>();
        Map<String, SourceMatch> variableToSourceMatch = new LinkedHashMap<>();
        Set<String> usedVariableNames = new LinkedHashSet<>();
        List<ResponseSnapshot> previousResponses = new ArrayList<>();
        Set<String> allowedHostRoots = determineAllowedHostRoots(originalEntries);

        int count = Math.min(originalEntries.size(), modifiedEntries.size());
        for (int i = 0; i < count; i++) {
            JsonNode originalEntryNode = originalEntries.get(i);
            JsonNode modifiedEntryNode = modifiedEntries.get(i);
            if (originalEntryNode instanceof ObjectNode originalEntry && modifiedEntryNode instanceof ObjectNode modifiedEntry) {
                JsonNode requestNode = modifiedEntry.path("request");
                if (requestNode instanceof ObjectNode request && isBusinessRequest(request, modifiedEntry.path("response"), allowedHostRoots)) {
                    rewriteQueryValues(request, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                    rewriteBodyValues(request, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);

                    JsonNode originalRequestNode = originalEntry.path("request");
                    RequestRef sourceRequest = toRequestRef(i + 1, originalRequestNode);
                    previousResponses.add(snapshotFromResponse(modifiedEntry.path("response"), sourceRequest));
                }
            }
        }

        ObjectNode variablesWrapper = objectMapper.createObjectNode();
        variablesWrapper.set("variables", objectMapper.valueToTree(variables));

        List<RewrittenRequest> rewrittenRequests = buildRewrittenRequests(
                originalEntries,
                modifiedEntries,
                allowedHostRoots,
                variableToSourceMatch,
                variables
        );
        String modifiedHarJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(modifiedRoot);
        String variablesJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(variablesWrapper);
        Map<String, String> regexByVariable = buildRegexByVariable(variableToSourceMatch, variables);
        return new AnalysisResult(variables, regexByVariable, variablesJson, modifiedHarJson, rewrittenRequests);
    }

    private List<RewrittenRequest> buildRewrittenRequests(
            ArrayNode originalEntries,
            ArrayNode modifiedEntries,
            Set<String> allowedHostRoots,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables
    ) {
        List<RewrittenRequest> requests = new ArrayList<>();
        Map<Integer, RewrittenRequest> modifiedByIndex = new HashMap<>();
        Set<Integer> sourceIndicesUsed = new HashSet<>();
        Map<Integer, String> sourceVariableNameByIndex = new HashMap<>();
        Map<Integer, String> sourceVariableValueByIndex = new HashMap<>();
        Map<Integer, String> sourceExtractionTypeByIndex = new HashMap<>();
        Map<Integer, String> sourceHeaderNameByIndex = new HashMap<>();
        Map<Integer, String> sourceHeaderValueByIndex = new HashMap<>();
        Map<Integer, String> sourceResponseBodyByIndex = new HashMap<>();
        Map<Integer, Map<String, String>> sourceVariablesByIndex = new HashMap<>();

        // Associate each extracted variable with its source request even if no rewritten request consumes it.
        for (Map.Entry<String, SourceMatch> entry : variableToSourceMatch.entrySet()) {
            String variableName = entry.getKey();
            SourceMatch match = entry.getValue();
            if (match == null || match.requestRef() == null) {
                continue;
            }
            registerSourceVariable(
                    match.requestRef(),
                    variableName,
                    variables.get(variableName),
                    match,
                    sourceIndicesUsed,
                    sourceVariableNameByIndex,
                    sourceVariableValueByIndex,
                    sourceExtractionTypeByIndex,
                    sourceHeaderNameByIndex,
                    sourceHeaderValueByIndex,
                    sourceResponseBodyByIndex,
                    sourceVariablesByIndex
            );
        }

        int count = Math.min(originalEntries.size(), modifiedEntries.size());
        for (int i = 0; i < count; i++) {
            int globalIndex = i + 1;
            JsonNode originalEntryNode = originalEntries.get(i);
            JsonNode modifiedEntryNode = modifiedEntries.get(i);
            JsonNode originalRequestNode = originalEntryNode.path("request");
            JsonNode modifiedRequestNode = modifiedEntryNode.path("request");
            if (!(originalRequestNode instanceof ObjectNode originalRequest) || !(modifiedRequestNode instanceof ObjectNode modifiedRequest)) {
                continue;
            }
            if (!isBusinessRequest(originalRequest, originalEntryNode.path("response"), allowedHostRoots)) {
                continue;
            }
            if (!containsVariableizedArgument(modifiedRequest)) {
                continue;
            }

            String method = modifiedRequest.path("method").asText("");
            String rewrittenUrl = modifiedRequest.path("url").asText("");
            String originalUrl = originalRequest.path("url").asText("");
            String name = deriveRequestName(rewrittenUrl);

            Map<String, String> originalHeaders = extractHeaders(originalRequest.path("headers"));
            Map<String, String> rewrittenHeaders = extractHeaders(modifiedRequest.path("headers"));
            String originalBody = originalRequest.path("postData").path("text").asText("");
            String rewrittenBody = modifiedRequest.path("postData").path("text").asText("");
            String sourceVariableName = null;
            SourceMatch sourceMatch = null;
            RequestRef sourceRef = null;
            String sourceVariableValue = null;
            Map<String, String> requestVariables = new LinkedHashMap<>();

            Set<String> variableNames = extractVariableNamesFromRequestArguments(modifiedRequest);
            for (String variableName : variableNames) {
                SourceMatch match = variableToSourceMatch.get(variableName);
                String value = variables.get(variableName);
                requestVariables.putIfAbsent(variableName, value);
                if (match == null) {
                    continue;
                }

                RequestRef ref = match.requestRef();
                if (ref != null) {
                    registerSourceVariable(
                            ref,
                            variableName,
                            value,
                            match,
                            sourceIndicesUsed,
                            sourceVariableNameByIndex,
                            sourceVariableValueByIndex,
                            sourceExtractionTypeByIndex,
                            sourceHeaderNameByIndex,
                            sourceHeaderValueByIndex,
                            sourceResponseBodyByIndex,
                            sourceVariablesByIndex
                    );
                }

                if (sourceVariableName == null) {
                    sourceVariableName = variableName;
                    sourceMatch = match;
                    sourceRef = ref;
                    sourceVariableValue = value;
                }
            }

            // Keep the SOURCE section aligned with the linked MODIFIED request:
            // once a primary source is selected for this request, show all variables
            // consumed by the request under that same source block.
            if (sourceRef != null && !requestVariables.isEmpty()) {
                sourceIndicesUsed.add(sourceRef.index());
                sourceVariablesByIndex
                        .computeIfAbsent(sourceRef.index(), k -> new LinkedHashMap<>())
                        .putAll(requestVariables);
            }

            modifiedByIndex.put(globalIndex, new RewrittenRequest(
                    globalIndex,
                    "MODIFIED",
                    name,
                    method,
                    sourceRef == null ? null : sourceRef.index(),
                    sourceRef == null ? null : sourceRef.name(),
                    sourceRef == null ? null : sourceRef.method(),
                    sourceRef == null ? null : sourceRef.url(),
                    sourceRef == null ? null : sourceRef.body(),
                    sourceVariableName,
                    sourceVariableValue,
                    sourceMatch == null ? null : sourceMatch.extractionType(),
                    sourceMatch == null ? null : sourceMatch.headerName(),
                    sourceMatch == null ? null : sourceMatch.headerValue(),
                    sourceMatch == null ? null : sourceMatch.responseBody(),
                    requestVariables,
                    originalUrl,
                    rewrittenUrl,
                    originalHeaders,
                    rewrittenHeaders,
                    originalBody,
                    rewrittenBody
            ));
        }

        for (int i = 0; i < count; i++) {
            int globalIndex = i + 1;
            JsonNode originalEntryNode = originalEntries.get(i);
            JsonNode originalRequestNode = originalEntryNode.path("request");
            if (!(originalRequestNode instanceof ObjectNode originalRequest)) {
                continue;
            }

            RewrittenRequest modified = modifiedByIndex.get(globalIndex);
            if (modified != null) {
                boolean isAlsoSource = sourceIndicesUsed.contains(globalIndex);
                Map<String, String> mergedSourceVariables = new LinkedHashMap<>();
                if (isAlsoSource) {
                    mergedSourceVariables.putAll(sourceVariablesByIndex.getOrDefault(globalIndex, Map.of()));
                }

                requests.add(new RewrittenRequest(
                        modified.index(),
                        modified.kind(),
                        modified.name(),
                        modified.method(),
                        modified.sourceIndex(),
                        modified.sourceName(),
                        modified.sourceMethod(),
                        modified.sourceUrl(),
                        modified.sourceBody(),
                        isAlsoSource ? sourceVariableNameByIndex.getOrDefault(globalIndex, modified.sourceVariableName()) : modified.sourceVariableName(),
                        isAlsoSource ? sourceVariableValueByIndex.getOrDefault(globalIndex, modified.sourceVariableValue()) : modified.sourceVariableValue(),
                        isAlsoSource ? sourceExtractionTypeByIndex.getOrDefault(globalIndex, modified.sourceExtractionType()) : modified.sourceExtractionType(),
                        isAlsoSource ? sourceHeaderNameByIndex.getOrDefault(globalIndex, modified.sourceHeaderName()) : modified.sourceHeaderName(),
                        isAlsoSource ? sourceHeaderValueByIndex.getOrDefault(globalIndex, modified.sourceHeaderValue()) : modified.sourceHeaderValue(),
                        isAlsoSource ? sourceResponseBodyByIndex.getOrDefault(globalIndex, modified.sourceResponseBody()) : modified.sourceResponseBody(),
                        mergedSourceVariables,
                        modified.originalUrl(),
                        modified.rewrittenUrl(),
                        modified.originalHeaders(),
                        modified.rewrittenHeaders(),
                        modified.originalBody(),
                        modified.rewrittenBody()
                ));
                continue;
            }

            String method = originalRequest.path("method").asText("");
            String url = originalRequest.path("url").asText("");
            String name = deriveRequestName(url);
            String body = originalRequest.path("postData").path("text").asText("");
            String kind = sourceIndicesUsed.contains(globalIndex) ? "SOURCE" : "PLAIN";
            requests.add(new RewrittenRequest(
                    globalIndex,
                    kind,
                    name,
                    method,
                    null,
                    null,
                    null,
                    null,
                    null,
                    "SOURCE".equals(kind) ? sourceVariableNameByIndex.get(globalIndex) : null,
                    "SOURCE".equals(kind) ? sourceVariableValueByIndex.get(globalIndex) : null,
                    "SOURCE".equals(kind) ? sourceExtractionTypeByIndex.get(globalIndex) : null,
                    "SOURCE".equals(kind) ? sourceHeaderNameByIndex.get(globalIndex) : null,
                    "SOURCE".equals(kind) ? sourceHeaderValueByIndex.get(globalIndex) : null,
                    "SOURCE".equals(kind) ? sourceResponseBodyByIndex.get(globalIndex) : null,
                    sourceVariablesByIndex.getOrDefault(globalIndex, Map.of()),
                    url,
                    url,
                    extractHeaders(originalRequest.path("headers")),
                    extractHeaders(originalRequest.path("headers")),
                    body,
                    body
            ));
        }

        return requests;
    }

    private void registerSourceVariable(
            RequestRef ref,
            String variableName,
            String value,
            SourceMatch match,
            Set<Integer> sourceIndicesUsed,
            Map<Integer, String> sourceVariableNameByIndex,
            Map<Integer, String> sourceVariableValueByIndex,
            Map<Integer, String> sourceExtractionTypeByIndex,
            Map<Integer, String> sourceHeaderNameByIndex,
            Map<Integer, String> sourceHeaderValueByIndex,
            Map<Integer, String> sourceResponseBodyByIndex,
            Map<Integer, Map<String, String>> sourceVariablesByIndex
    ) {
        int sourceIndex = ref.index();
        sourceIndicesUsed.add(sourceIndex);
        sourceVariableNameByIndex.putIfAbsent(sourceIndex, variableName);
        sourceVariableValueByIndex.putIfAbsent(sourceIndex, value);
        sourceExtractionTypeByIndex.putIfAbsent(sourceIndex, match.extractionType());
        sourceHeaderNameByIndex.putIfAbsent(sourceIndex, match.headerName());
        sourceHeaderValueByIndex.putIfAbsent(sourceIndex, match.headerValue());
        sourceResponseBodyByIndex.putIfAbsent(sourceIndex, match.responseBody());
        sourceVariablesByIndex
                .computeIfAbsent(sourceIndex, k -> new LinkedHashMap<>())
                .putIfAbsent(variableName, value);
    }

    private Map<String, String> extractHeaders(JsonNode headersNode) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (headersNode instanceof ArrayNode headerArray) {
            for (JsonNode headerNode : headerArray) {
                String headerName = headerNode.path("name").asText("");
                String headerValue = headerNode.path("value").asText("");
                if (!headerName.isBlank() && !headerValue.isBlank()) {
                    headers.put(headerName, headerValue);
                }
            }
        }
        return headers;
    }

    private Set<String> extractVariableNamesFromRequestArguments(ObjectNode request) {
        Set<String> names = new LinkedHashSet<>();

        JsonNode queryNode = request.path("queryString");
        if (queryNode instanceof ArrayNode queryString) {
            for (JsonNode paramNode : queryString) {
                collectVariableNames(paramNode.path("value").asText(""), names);
            }
        }

        String url = request.path("url").asText("");
        if (url.contains("?")) {
            int queryStart = url.indexOf('?');
            int fragmentStart = url.indexOf('#');
            int end = fragmentStart >= 0 ? fragmentStart : url.length();
            if (queryStart >= 0 && queryStart + 1 < end) {
                collectVariableNames(url.substring(queryStart + 1, end), names);
            }
        }

        JsonNode postDataNode = request.path("postData");
        if (postDataNode instanceof ObjectNode postData) {
            JsonNode paramsNode = postData.path("params");
            if (paramsNode instanceof ArrayNode params) {
                for (JsonNode paramNode : params) {
                    collectVariableNames(paramNode.path("value").asText(""), names);
                }
            }
            collectVariableNames(postData.path("text").asText(""), names);
        }

        return names;
    }

    private void collectVariableNames(String text, Set<String> target) {
        if (text == null || text.isBlank()) {
            return;
        }
        Matcher direct = VAR_TOKEN.matcher(text);
        while (direct.find()) {
            target.add(direct.group(1));
        }

        String decoded = decode(text);
        Matcher decodedMatcher = VAR_TOKEN.matcher(decoded);
        while (decodedMatcher.find()) {
            target.add(decodedMatcher.group(1));
        }
    }

    private boolean containsVariableizedArgument(ObjectNode request) {
        JsonNode queryNode = request.path("queryString");
        if (queryNode instanceof ArrayNode queryString) {
            for (JsonNode paramNode : queryString) {
                if (containsVariableToken(paramNode.path("value").asText(""))) {
                    return true;
                }
            }
        }

        String url = request.path("url").asText("");
        if (containsVariableToken(url)) {
            return true;
        }

        JsonNode postDataNode = request.path("postData");
        if (postDataNode instanceof ObjectNode postData) {
            JsonNode paramsNode = postData.path("params");
            if (paramsNode instanceof ArrayNode params) {
                for (JsonNode paramNode : params) {
                    if (containsVariableToken(paramNode.path("value").asText(""))) {
                        return true;
                    }
                }
            }

            if (containsVariableToken(postData.path("text").asText(""))) {
                return true;
            }
        }
        return false;
    }

    private boolean containsVariableToken(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        if (value.contains("${")) {
            return true;
        }
        String decoded = decode(value);
        if (decoded.contains("${")) {
            return true;
        }
        return value.matches(".*\\$\\{[^}]+}.*") || decoded.matches(".*\\$\\{[^}]+}.*");
    }

    private Set<String> determineAllowedHostRoots(ArrayNode entries) {
        Map<String, Integer> hostCounts = new HashMap<>();

        for (JsonNode entryNode : entries) {
            JsonNode requestNode = entryNode.path("request");
            if (!(requestNode instanceof ObjectNode request)) {
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

        String primaryRoot = hostRoot(primaryHost);
        Set<String> roots = new HashSet<>();
        roots.add(primaryRoot);
        return roots;
    }

    private boolean isBusinessRequest(JsonNode request, JsonNode response, Set<String> allowedHostRoots) {
        String url = request.path("url").asText("");
        if (!isHttpOrHttps(url)) {
            return false;
        }

        String host = extractHost(url);
        if (host.isBlank()) {
            return false;
        }
        if (isKnownThirdPartyHost(host)) {
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
        String ext = path.substring(dot + 1);
        return STATIC_EXTENSIONS.contains(ext);
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
            String name = header.path("name").asText("");
            if (name.equalsIgnoreCase(headerName)) {
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
        if (normalized.equals("localhost") || normalized.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return normalized;
        }
        String[] parts = normalized.split("\\.");
        if (parts.length < 2) {
            return normalized;
        }
        return parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    private void rewriteQueryValues(
            ObjectNode request,
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            List<ResponseSnapshot> previousResponses
    ) {
        JsonNode queryNode = request.path("queryString");
        if (queryNode instanceof ArrayNode queryString) {
            for (JsonNode paramNode : queryString) {
                if (!(paramNode instanceof ObjectNode param)) {
                    continue;
                }
                String name = param.path("name").asText("query_param");
                String value = param.path("value").asText("");
                String variableName = resolveVariableName(name, value, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                if (variableName != null) {
                    param.put("value", "${" + variableName + "}");
                }
            }
        }

        String url = request.path("url").asText("");
        if (url.isBlank()) {
            return;
        }

        int fragmentStart = url.indexOf('#');
        String fragment = fragmentStart >= 0 ? url.substring(fragmentStart) : "";
        String withoutFragment = fragmentStart >= 0 ? url.substring(0, fragmentStart) : url;

        int queryStart = withoutFragment.indexOf('?');
        if (queryStart < 0) {
            return;
        }

        String base = withoutFragment.substring(0, queryStart);
        String query = withoutFragment.substring(queryStart + 1);

        String[] pairs = query.split("&", -1);
        StringBuilder rebuilt = new StringBuilder();
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                rebuilt.append('&');
            }

            String pair = pairs[i];
            if (pair.isBlank()) {
                rebuilt.append(pair);
                continue;
            }

            String[] split = pair.split("=", 2);
            String rawName = split[0];
            String rawValue = split.length > 1 ? split[1] : "";
            String name = decode(rawName);
            String value = decode(rawValue);

            String variableName = resolveVariableName(name, value, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
            rebuilt.append(rawName);
            if (split.length > 1) {
                rebuilt.append('=');
                if (variableName != null) {
                    rebuilt.append("${").append(variableName).append('}');
                } else {
                    rebuilt.append(rawValue);
                }
            }
        }

        request.put("url", base + "?" + rebuilt + fragment);
    }

    private void rewriteBodyValues(
            ObjectNode request,
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            List<ResponseSnapshot> previousResponses
    ) {
        JsonNode postDataNode = request.path("postData");
        if (!(postDataNode instanceof ObjectNode postData)) {
            return;
        }

        JsonNode paramsNode = postData.path("params");
        if (paramsNode instanceof ArrayNode params) {
            for (JsonNode paramNode : params) {
                if (!(paramNode instanceof ObjectNode param)) {
                    continue;
                }
                String name = param.path("name").asText("body_param");
                String value = param.path("value").asText("");
                String variableName = resolveVariableName(name, value, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                if (variableName != null) {
                    param.put("value", "${" + variableName + "}");
                }
            }
        }

        String text = postData.path("text").asText("");
        if (text.isBlank()) {
            return;
        }

        String mimeType = postData.path("mimeType").asText("").toLowerCase(Locale.ROOT);
        if (looksLikeJson(text) || mimeType.contains("json")) {
            try {
                JsonNode json = objectMapper.readTree(text);
                if (json instanceof ObjectNode obj) {
                    rewriteJsonObject(obj, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                    postData.put("text", objectMapper.writeValueAsString(obj));
                    return;
                }
                if (json instanceof ArrayNode arr) {
                    rewriteJsonArray(arr, "body", valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                    postData.put("text", objectMapper.writeValueAsString(arr));
                    return;
                }
            } catch (Exception ignored) {
                // Fallback on form-like body parsing.
            }
        }

        if (text.contains("=")) {
            postData.put("text", rewriteFormLikeBody(text, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses));
        }
    }

    private void rewriteJsonObject(
            ObjectNode object,
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            List<ResponseSnapshot> previousResponses
    ) {
        List<String> fieldNames = new ArrayList<>();
        object.fieldNames().forEachRemaining(fieldNames::add);

        for (String fieldName : fieldNames) {
            JsonNode child = object.get(fieldName);
            if (child == null || child.isNull()) {
                continue;
            }

            if (child.isValueNode()) {
                String value = child.asText("");
                String variableName = resolveVariableName(fieldName, value, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                if (variableName != null) {
                    object.put(fieldName, "${" + variableName + "}");
                }
                continue;
            }

            if (child instanceof ObjectNode nestedObject) {
                rewriteJsonObject(nestedObject, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                continue;
            }

            if (child instanceof ArrayNode nestedArray) {
                rewriteJsonArray(nestedArray, fieldName, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
            }
        }
    }

    private void rewriteJsonArray(
            ArrayNode array,
            String nameHint,
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            List<ResponseSnapshot> previousResponses
    ) {
        for (int i = 0; i < array.size(); i++) {
            JsonNode child = array.get(i);
            if (child == null || child.isNull()) {
                continue;
            }

            if (child.isValueNode()) {
                String value = child.asText("");
                String variableName = resolveVariableName(nameHint, value, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                if (variableName != null) {
                    array.set(i, objectMapper.getNodeFactory().textNode("${" + variableName + "}"));
                }
                continue;
            }

            if (child instanceof ObjectNode nestedObject) {
                rewriteJsonObject(nestedObject, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
                continue;
            }

            if (child instanceof ArrayNode nestedArray) {
                rewriteJsonArray(nestedArray, nameHint, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);
            }
        }
    }

    private String rewriteFormLikeBody(
            String text,
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            List<ResponseSnapshot> previousResponses
    ) {
        String[] pairs = text.split("&", -1);
        StringBuilder rewritten = new StringBuilder();
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) {
                rewritten.append('&');
            }

            String pair = pairs[i];
            if (pair.isBlank()) {
                rewritten.append(pair);
                continue;
            }

            String[] split = pair.split("=", 2);
            String rawName = split[0];
            String rawValue = split.length > 1 ? split[1] : "";
            String name = decode(rawName);
            String value = decode(rawValue);
            String variableName = resolveVariableName(name, value, valueToVariable, variableToSourceMatch, variables, usedVariableNames, previousResponses);

            rewritten.append(rawName);
            if (split.length > 1) {
                rewritten.append('=');
                if (variableName != null) {
                    rewritten.append("${").append(variableName).append('}');
                } else {
                    rewritten.append(rawValue);
                }
            }
        }
        return rewritten.toString();
    }

    private String resolveVariableName(
            String parameterName,
            String value,
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            List<ResponseSnapshot> previousResponses
    ) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalizedValue = value.trim();
        if (normalizedValue.startsWith("${") && normalizedValue.endsWith("}")) {
            return null;
        }
        if (shouldExcludeFromVariableization(parameterName, normalizedValue)) {
            return null;
        }

        String existing = valueToVariable.get(normalizedValue);
        if (existing != null) {
            return existing;
        }

        SourceMatch sourceMatch = findFirstSourceMatch(parameterName, normalizedValue, previousResponses);
        if (sourceMatch == null) {
            return null;
        }

        String variableName = uniqueVariableName(parameterName, usedVariableNames);
        usedVariableNames.add(variableName);
        valueToVariable.put(normalizedValue, variableName);
        variableToSourceMatch.put(variableName, sourceMatch);
        variables.put(variableName, normalizedValue);
        return variableName;
    }

    private ResponseSnapshot snapshotFromResponse(JsonNode response, RequestRef requestRef) {
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

    private SourceMatch findFirstSourceMatch(String parameterName, String value, List<ResponseSnapshot> previousResponses) {
        for (ResponseSnapshot snapshot : previousResponses) {
            String requestUrl = snapshot.requestRef().url();
            if (containsNamedOccurrence(requestUrl, parameterName, value)) {
                return new SourceMatch(snapshot.requestRef(), "REQUEST", null, null, requestUrl, parameterName);
            }

            String requestBody = snapshot.requestRef().body();
            if (containsNamedOccurrence(requestBody, parameterName, value)) {
                return new SourceMatch(snapshot.requestRef(), "REQUEST", null, null, requestBody, parameterName);
            }

            String body = snapshot.bodyText();
            if (containsNamedOccurrence(body, parameterName, value)) {
                return new SourceMatch(snapshot.requestRef(), "BODY", null, null, body, parameterName);
            }

            for (Map.Entry<String, String> header : snapshot.headers().entrySet()) {
                String headerValue = header.getValue();
                if (headerValue != null && headerValue.contains(value)) {
                    return new SourceMatch(snapshot.requestRef(), "HEADER", header.getKey(), headerValue, snapshot.bodyText(), parameterName);
                }
            }
            if (body != null && body.contains(value)) {
                return new SourceMatch(snapshot.requestRef(), "BODY", null, null, body, parameterName);
            }

            // Fallback: some correlated values are propagated from prior request URL/body,
            // not only from response payload/headers.
            if (requestBody != null && requestBody.contains(value)) {
                return new SourceMatch(snapshot.requestRef(), "REQUEST", null, null, requestBody, parameterName);
            }
            if (requestUrl != null) {
                String directNeedle = Objects.toString(parameterName, "") + "=" + value;
                String decodedUrl = decode(requestUrl);
                if (!Objects.toString(parameterName, "").isBlank() && requestUrl.contains(directNeedle)) {
                    return new SourceMatch(snapshot.requestRef(), "REQUEST", null, null, requestUrl, parameterName);
                }
                if (!Objects.toString(parameterName, "").isBlank() && !decodedUrl.equals(requestUrl) && decodedUrl.contains(directNeedle)) {
                    return new SourceMatch(snapshot.requestRef(), "REQUEST", null, null, decodedUrl, parameterName);
                }
                if (requestUrl.contains(value)) {
                    return new SourceMatch(snapshot.requestRef(), "REQUEST", null, null, requestUrl, parameterName);
                }
                if (!decodedUrl.equals(requestUrl) && decodedUrl.contains(value)) {
                    return new SourceMatch(snapshot.requestRef(), "REQUEST", null, null, decodedUrl, parameterName);
                }
            }
        }
        return null;
    }

    private boolean containsNamedOccurrence(String text, String parameterName, String value) {
        if (text == null || text.isBlank() || parameterName == null || parameterName.isBlank() || value == null || value.isBlank()) {
            return false;
        }

        if (text.contains(parameterName + "=" + value)
                || text.contains(parameterName + "\\u003d" + value)
                || text.contains("\"" + parameterName + "\":\"" + value + "\"")
                || text.contains("\\\"" + parameterName + "\\\":\\\"" + value + "\\\"")) {
            return true;
        }

        String decoded = decode(text);
        return !decoded.equals(text) && decoded.contains(parameterName + "=" + value);
    }

    private String uniqueVariableName(String sourceName, Set<String> usedNames) {
        String base = toSafeVariableName(sourceName);
        String candidate = base;
        int i = 2;
        while (usedNames.contains(candidate)) {
            candidate = base + "_" + i;
            i++;
        }
        return candidate;
    }

    private String toSafeVariableName(String raw) {
        String normalized = Objects.toString(raw, "var").trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            normalized = "var";
        }
        normalized = VAR_SAFE.matcher(normalized).replaceAll("_");
        normalized = normalized.replaceAll("_+", "_");
        if (normalized.startsWith("_")) {
            normalized = normalized.substring(1);
        }
        if (normalized.isBlank()) {
            normalized = "var";
        }
        if (Character.isDigit(normalized.charAt(0))) {
            normalized = "var_" + normalized;
        }
        return normalized;
    }

    private boolean looksLikeJson(String text) {
        String trimmed = text.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    private String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private boolean shouldExcludeFromVariableization(String parameterName, String value) {
        if (isExcludedParameterName(parameterName)) {
            return true;
        }
        return looksLikeUrlOrPath(value);
    }

    private boolean isExcludedParameterName(String parameterName) {
        String normalized = normalizeParameterName(parameterName);
        if (normalized.isBlank()) {
            return false;
        }
        return EXCLUDED_DYNAMIC_PARAM_NAMES.contains(normalized);
    }

    private String normalizeParameterName(String parameterName) {
        String raw = Objects.toString(parameterName, "").toLowerCase(Locale.ROOT);
        return raw.replaceAll("[^a-z0-9]", "");
    }

    private boolean looksLikeUrlOrPath(String value) {
        String raw = Objects.toString(value, "").trim();
        if (raw.isBlank()) {
            return false;
        }

        String decoded = decode(raw).trim();
        String lowerRaw = raw.toLowerCase(Locale.ROOT);
        String lowerDecoded = decoded.toLowerCase(Locale.ROOT);

        if (lowerRaw.startsWith("http://") || lowerRaw.startsWith("https://")
                || lowerDecoded.startsWith("http://") || lowerDecoded.startsWith("https://")) {
            return true;
        }
        if (lowerRaw.startsWith("//") || lowerDecoded.startsWith("//")) {
            return true;
        }
        if (raw.startsWith("/") || decoded.startsWith("/")
                || raw.startsWith("./") || decoded.startsWith("./")
                || raw.startsWith("../") || decoded.startsWith("../")) {
            return true;
        }
        if (lowerRaw.contains("://") || lowerDecoded.contains("://")) {
            return true;
        }
        if (raw.contains("\\") || decoded.contains("\\")) {
            return true;
        }

        // Covers paths like "oauth/authorize" or "api/v1/items" without protocol.
        if ((raw.contains("/") || decoded.contains("/")) && !(raw.contains(" ") || decoded.contains(" "))) {
            return true;
        }

        try {
            URI uri = URI.create(decoded);
            if (uri.getHost() != null) {
                return true;
            }
            if (uri.getPath() != null && !uri.getPath().isBlank() && uri.getPath().startsWith("/")) {
                return true;
            }
        } catch (Exception ignored) {
            // Keep best-effort heuristics above.
        }

        return false;
    }

    private String deriveRequestName(String url) {
        String path = extractPath(url);
        if (path.isBlank() || "/".equals(path)) {
            return "/";
        }

        String[] segments = path.split("/");
        String fallback = null;
        for (int i = segments.length - 1; i >= 0; i--) {
            String segment = decode(segments[i]).trim();
            if (segment.isBlank()) {
                continue;
            }
            if (fallback == null) {
                fallback = segment;
            }
            if (segment.matches(".*[A-Za-z].*")) {
                return segment;
            }
        }
        return fallback == null ? path : fallback;
    }

    private String extractPath(String url) {
        try {
            String path = URI.create(url).getPath();
            if (path == null || path.isBlank()) {
                return "/";
            }
            return path;
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
                if (startPath >= 0) {
                    return trimmed.substring(startPath);
                }
                return "/";
            }
            return trimmed.isBlank() ? "/" : trimmed;
        }
    }

    private RequestRef toRequestRef(int index, JsonNode requestNode) {
        if (!(requestNode instanceof ObjectNode request)) {
            return new RequestRef(index, "request_" + index, "", "", "");
        }
        String method = request.path("method").asText("");
        String url = request.path("url").asText("");
        String name = deriveRequestName(url);
        String body = request.path("postData").path("text").asText("");
        return new RequestRef(index, name, method, url, body);
    }
    private Map<String, String> buildRegexByVariable(Map<String, SourceMatch> variableToSourceMatch, Map<String, String> variables) {
        Map<String, String> out = new LinkedHashMap<>();
        if (variableToSourceMatch == null || variableToSourceMatch.isEmpty() || variables == null || variables.isEmpty()) {
            return out;
        }

        for (Map.Entry<String, SourceMatch> entry : variableToSourceMatch.entrySet()) {
            String variableName = entry.getKey();
            if (variableName == null || variableName.isBlank()) {
                continue;
            }
            String value = variables.get(variableName);
            String regex = buildExtractionRegex(entry.getValue(), value);
            if (regex != null && !regex.isBlank()) {
                out.put(variableName, regex);
            }
        }
        return out;
    }

    private String buildExtractionRegex(SourceMatch match, String value) {
        if (match == null || value == null || value.isBlank()) {
            return null;
        }

        String extractionType = Objects.toString(match.extractionType(), "");
        if ("HEADER".equals(extractionType)) {
            return buildDelimitedRegex(Objects.toString(match.headerValue(), ""), value, 16, 16);
        }

        String response = Objects.toString(match.responseBody(), "");
        String requestUrl = match.requestRef() == null ? "" : Objects.toString(match.requestRef().url(), "");
        String requestBody = match.requestRef() == null ? "" : Objects.toString(match.requestRef().body(), "");

        String urlParamRegex = firstNonBlank(
                tryBuildUrlParamRegex(requestUrl, value, match.parameterName()),
                tryBuildUrlParamRegex(response, value, match.parameterName()),
                tryBuildUrlParamRegex(requestBody, value, match.parameterName())
        );
        if (urlParamRegex != null) {
            return urlParamRegex;
        }

        String jsonFieldRegex = firstNonBlank(
                tryBuildJsonStringFieldRegex(response, value, match.parameterName()),
                tryBuildJsonStringFieldRegex(requestBody, value, match.parameterName()),
                tryBuildJsonStringFieldRegex(requestUrl, value, match.parameterName())
        );
        if (jsonFieldRegex != null) {
            return jsonFieldRegex;
        }

        String candidate = firstContaining(value, response, requestUrl, requestBody);
        if (candidate.isBlank()) {
            return null;
        }
        return buildDelimitedRegex(candidate, value, 16, 16);
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private String firstContaining(String needle, String... candidates) {
        if (needle == null || needle.isBlank() || candidates == null) {
            return "";
        }
        for (String c : candidates) {
            if (c == null || c.isBlank()) {
                continue;
            }
            if (c.contains(needle)) {
                return c;
            }
        }
        return "";
    }

    private String tryBuildUrlParamRegex(String text, String value, String parameterName) {
        if (text == null || text.isBlank() || value == null || value.isBlank()) {
            return null;
        }

        String normalizedParameterName = Objects.toString(parameterName, "").trim();
        if (normalizedParameterName.isBlank()) {
            return null;
        }

        for (String separator : URL_PARAM_SEPARATORS) {
            for (String assignment : URL_PARAM_ASSIGNMENTS) {
                String needle = separator + normalizedParameterName + assignment + value;
                int start = text.indexOf(needle);
                if (start < 0) {
                    continue;
                }
                String prefix = buildUrlPrefix(text, start, separator, normalizedParameterName, assignment);
                int valueStart = start + separator.length() + normalizedParameterName.length() + assignment.length();
                int afterIdx = valueStart + value.length();
                String regex = appendUrlSuffix(text, prefix, afterIdx, URL_PARAM_SUFFIXES);
                if (regex != null) {
                    return regex;
                }
            }
        }

        for (String assignment : URL_PARAM_ASSIGNMENTS) {
            String needle = normalizedParameterName + assignment + value;
            int start = text.indexOf(needle);
            if (start < 0) {
                continue;
            }
            String prefix = normalizedParameterName + assignment;
            int afterIdx = start + normalizedParameterName.length() + assignment.length() + value.length();
            String regex = appendUrlSuffix(text, prefix, afterIdx, URL_PARAM_SUFFIXES);
            if (regex != null) {
                return regex;
            }
        }
        return null;
    }

    private String buildUrlPrefix(String text, int start, String separator, String parameterName, String assignment) {
        if ("?".equals(separator)) {
            String lastSegment = lastPathSegment(text);
            if (!lastSegment.isBlank()) {
                return lastSegment + separator + parameterName + assignment;
            }
        }
        return parameterName + assignment;
    }

    private String appendUrlSuffix(String text, String prefix, int afterIdx, String[] suffixes) {
        StringBuilder regex = new StringBuilder(96);
        regex.append(regexEscapeLiteral(prefix));
        regex.append("(.+?)");

        if (afterIdx >= text.length()) {
            return regex.toString();
        }

        for (String suffix : suffixes) {
            if (text.startsWith(suffix, afterIdx)) {
                regex.append(regexEscapeLiteral(suffix));
                return regex.toString();
            }
        }

        return regex.toString();
    }

    private String lastPathSegment(String text) {
        try {
            URI uri = URI.create(text);
            String path = Objects.toString(uri.getPath(), "");
            if (path.isBlank()) {
                return "";
            }
            int slash = path.lastIndexOf('/');
            return slash >= 0 ? path.substring(slash + 1) : path;
        } catch (Exception ignored) {
            int q = text.indexOf('?');
            String before = q >= 0 ? text.substring(0, q) : text;
            int slash = before.lastIndexOf('/');
            if (slash < 0 || slash + 1 >= before.length()) {
                return "";
            }
            return before.substring(slash + 1);
        }
    }

    private String tryBuildJsonStringFieldRegex(String text, String value, String parameterName) {
        if (text == null || text.isBlank() || value == null || value.isBlank()) {
            return null;
        }

        String expectedKey = Objects.toString(parameterName, "").trim();
        if (!expectedKey.isBlank()) {
            String plainNeedle = "\"" + expectedKey + "\":\"" + value + "\"";
            if (text.contains(plainNeedle)) {
                return "\"" + regexEscapeLiteral(expectedKey) + "\"\\s*:\\s*\"(.+?)\"";
            }

            String escapedNeedle = "\\\"" + expectedKey + "\\\":\\\"" + value + "\\\"";
            if (text.contains(escapedNeedle)) {
                return "\\\\\"" + regexEscapeLiteral(expectedKey) + "\\\\\":\\\\\"(.+?)\\\\\"";
            }
        }

        int idx = text.indexOf(value);
        if (idx < 0) {
            return null;
        }

        Matcher m = JSON_STRING_FIELD_PREFIX.matcher(text);
        while (m.find()) {
            int valueStart = m.end();
            if (valueStart == idx) {
                String key = m.group(1);
                if (key != null && !key.isBlank() && (expectedKey.isBlank() || key.equals(expectedKey))) {
                    return "\"" + regexEscapeLiteral(key) + "\"\\s*:\\s*\"(.+?)\"";
                }
            }
        }

        return null;
    }

    private String buildDelimitedRegex(String haystack, String value, int beforeLimit, int afterLimit) {
        if (haystack == null || haystack.isBlank() || value == null || value.isBlank()) {
            return null;
        }

        int idx = haystack.indexOf(value);
        if (idx < 0) {
            return null;
        }

        String before = extractMinimalPrefix(haystack, idx, beforeLimit);
        String after = extractMinimalSuffix(haystack, idx + value.length(), afterLimit);

        StringBuilder regex = new StringBuilder(128);
        if (!before.isEmpty()) {
            regex.append(regexEscapeLiteral(before));
        }
        regex.append("(.+?)");
        if (!after.isEmpty()) {
            regex.append(regexEscapeLiteral(after));
        }
        return regex.toString();
    }

    private String extractMinimalPrefix(String text, int valueStart, int beforeLimit) {
        if (text == null || text.isBlank() || valueStart <= 0) {
            return "";
        }

        int lowerBound = Math.max(0, valueStart - Math.max(0, beforeLimit));
        int start = valueStart;
        while (start > lowerBound) {
            char current = text.charAt(start - 1);
            if (Character.isLetterOrDigit(current) || current == '_' || current == '-' || current == '=' || current == ':') {
                start--;
                continue;
            }
            break;
        }
        return text.substring(start, valueStart);
    }

    private String extractMinimalSuffix(String text, int valueEnd, int afterLimit) {
        if (text == null || text.isBlank() || valueEnd < 0 || valueEnd >= text.length()) {
            return "";
        }

        int upperBound = Math.min(text.length(), valueEnd + Math.max(0, afterLimit));
        int end = valueEnd;
        while (end < upperBound) {
            char current = text.charAt(end);
            if (!Character.isLetterOrDigit(current) && current != '_' && current != '-') {
                end++;
                if (current == '\\' && end < upperBound) {
                    end++;
                }
                break;
            }
            break;
        }
        return text.substring(valueEnd, end);
    }

    private String regexEscapeLiteral(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return text.replace("\\", "\\\\")
                .replace(".", "\\.")
                .replace("^", "\\^")
                .replace("$", "\\$")
                .replace("*", "\\*")
                .replace("+", "\\+")
                .replace("?", "\\?")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .replace("[", "\\[")
                .replace("]", "\\]")
                .replace("{", "\\{")
                .replace("}", "\\}")
                .replace("|", "\\|");
    }

    private record RequestRef(
            int index,
            String name,
            String method,
            String url,
            String body
    ) {
    }

    private record SourceMatch(
            RequestRef requestRef,
            String extractionType,
            String headerName,
            String headerValue,
            String responseBody,
            String parameterName
    ) {
    }

    private record ResponseSnapshot(
            String bodyText,
            Map<String, String> headers,
            RequestRef requestRef
    ) {
    }
}
