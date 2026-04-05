package com.ngenia.harparam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ngenia.harparam.model.AnalysisResult;
import com.ngenia.harparam.model.RewrittenRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author bpabdelkader
 */
@Service
public class HarAnalysisService {

    private static final Pattern VAR_SAFE = Pattern.compile("[^a-zA-Z0-9_]");
    private static final Pattern VAR_TOKEN = Pattern.compile("\\$\\{([^}]+)}");
    private static final Pattern UNDERSCORE_RUNS = Pattern.compile("_+");
    private static final Pattern NON_ALNUM_LOWER = Pattern.compile("[^a-z0-9]");
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
    private final HarRequestClassifier requestClassifier;
    private final SourceMatchFinder sourceMatchFinder;
    private final CorrelationRegexBuilder regexBuilder;

    public HarAnalysisService(ObjectMapper objectMapper) {
        this(
                objectMapper,
                new HarRequestClassifier(),
                new SourceMatchFinder(),
                new CorrelationRegexBuilder()
        );
    }

    @Autowired
    public HarAnalysisService(
            ObjectMapper objectMapper,
            HarRequestClassifier requestClassifier,
            SourceMatchFinder sourceMatchFinder,
            CorrelationRegexBuilder regexBuilder
    ) {
        this.objectMapper = objectMapper;
        this.requestClassifier = requestClassifier;
        this.sourceMatchFinder = sourceMatchFinder;
        this.regexBuilder = regexBuilder;
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
        SourceMatchFinder.SourceSearchIndex sourceSearchIndex = sourceMatchFinder.newIndex();
        Set<String> allowedHostRoots = requestClassifier.determineAllowedHostRoots(originalEntries);
        RewriteContext rewriteContext = new RewriteContext(
                valueToVariable,
                variableToSourceMatch,
                variables,
                usedVariableNames,
                sourceSearchIndex
        );

        int count = Math.min(originalEntries.size(), modifiedEntries.size());
        for (int i = 0; i < count; i++) {
            JsonNode originalEntryNode = originalEntries.get(i);
            JsonNode modifiedEntryNode = modifiedEntries.get(i);
            if (originalEntryNode instanceof ObjectNode originalEntry && modifiedEntryNode instanceof ObjectNode modifiedEntry) {
                JsonNode requestNode = modifiedEntry.path("request");
                if (requestNode instanceof ObjectNode request && requestClassifier.isBusinessRequest(request, modifiedEntry.path("response"), allowedHostRoots)) {
                    rewriteQueryValues(request, rewriteContext);
                    rewriteBodyValues(request, rewriteContext);

                    JsonNode originalRequestNode = originalEntry.path("request");
                    RequestRef sourceRequest = toRequestRef(i + 1, originalRequestNode);
                    sourceSearchIndex.add(sourceMatchFinder.snapshotFromResponse(modifiedEntry.path("response"), sourceRequest));
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
        Map<String, String> regexByVariable = regexBuilder.buildRegexByVariable(variableToSourceMatch, variables);
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
        Map<Integer, SourceMetadata> sourceMetadataByIndex = new HashMap<>();

        // Associate each extracted variable with its source request even if no rewritten request consumes it.
        for (Map.Entry<String, SourceMatch> entry : variableToSourceMatch.entrySet()) {
            String variableName = entry.getKey();
            SourceMatch match = entry.getValue();
            if (match == null || match.requestRef() == null) {
                continue;
            }
            registerSourceVariable(match.requestRef(), variableName, variables.get(variableName), match, sourceMetadataByIndex);
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
            if (!requestClassifier.isBusinessRequest(originalRequest, originalEntryNode.path("response"), allowedHostRoots)) {
                continue;
            }
            if (!containsVariableizedArgument(modifiedRequest)) {
                continue;
            }

            String method = modifiedRequest.path("method").asText("");
            String rewrittenUrl = modifiedRequest.path("url").asText("");
            String originalUrl = originalRequest.path("url").asText("");
            String name = deriveRequestName(rewrittenUrl);
            String startedDateTime = originalEntryNode.path("startedDateTime").asText("");

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
                    registerSourceVariable(ref, variableName, value, match, sourceMetadataByIndex);
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
                sourceMetadataByIndex
                        .computeIfAbsent(sourceRef.index(), k -> new SourceMetadata())
                        .variables
                        .putAll(requestVariables);
            }

            modifiedByIndex.put(globalIndex, new RewrittenRequest(
                    globalIndex,
                    "MODIFIED",
                    name,
                    method,
                    startedDateTime,
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
                SourceMetadata sourceMetadata = sourceMetadataByIndex.get(globalIndex);
                boolean isAlsoSource = sourceMetadata != null;
                Map<String, String> mergedSourceVariables = isAlsoSource ? new LinkedHashMap<>(sourceMetadata.variables) : Map.of();

                requests.add(new RewrittenRequest(
                        modified.index(),
                        modified.kind(),
                        modified.name(),
                        modified.method(),
                        modified.startedDateTime(),
                        modified.sourceIndex(),
                        modified.sourceName(),
                        modified.sourceMethod(),
                        modified.sourceUrl(),
                        modified.sourceBody(),
                        isAlsoSource ? firstNonNull(sourceMetadata.variableName, modified.sourceVariableName()) : modified.sourceVariableName(),
                        isAlsoSource ? firstNonNull(sourceMetadata.variableValue, modified.sourceVariableValue()) : modified.sourceVariableValue(),
                        isAlsoSource ? firstNonNull(sourceMetadata.extractionType, modified.sourceExtractionType()) : modified.sourceExtractionType(),
                        isAlsoSource ? firstNonNull(sourceMetadata.headerName, modified.sourceHeaderName()) : modified.sourceHeaderName(),
                        isAlsoSource ? firstNonNull(sourceMetadata.headerValue, modified.sourceHeaderValue()) : modified.sourceHeaderValue(),
                        isAlsoSource ? firstNonNull(sourceMetadata.responseBody, modified.sourceResponseBody()) : modified.sourceResponseBody(),
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
            String startedDateTime = originalEntryNode.path("startedDateTime").asText("");
            SourceMetadata sourceMetadata = sourceMetadataByIndex.get(globalIndex);
            String kind = sourceMetadata != null ? "SOURCE" : "PLAIN";
            Map<String, String> headers = extractHeaders(originalRequest.path("headers"));
            requests.add(new RewrittenRequest(
                    globalIndex,
                    kind,
                    name,
                    method,
                    startedDateTime,
                    null,
                    null,
                    null,
                    null,
                    null,
                    sourceMetadata == null ? null : sourceMetadata.variableName,
                    sourceMetadata == null ? null : sourceMetadata.variableValue,
                    sourceMetadata == null ? null : sourceMetadata.extractionType,
                    sourceMetadata == null ? null : sourceMetadata.headerName,
                    sourceMetadata == null ? null : sourceMetadata.headerValue,
                    sourceMetadata == null ? null : sourceMetadata.responseBody,
                    sourceMetadata == null ? Map.of() : sourceMetadata.variables,
                    url,
                    url,
                    headers,
                    headers,
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
            Map<Integer, SourceMetadata> sourceMetadataByIndex
    ) {
        SourceMetadata sourceMetadata = sourceMetadataByIndex.computeIfAbsent(ref.index(), k -> new SourceMetadata());
        sourceMetadata.variableName = firstNonNull(sourceMetadata.variableName, variableName);
        sourceMetadata.variableValue = firstNonNull(sourceMetadata.variableValue, value);
        sourceMetadata.extractionType = firstNonNull(sourceMetadata.extractionType, match.extractionType());
        sourceMetadata.headerName = firstNonNull(sourceMetadata.headerName, match.headerName());
        sourceMetadata.headerValue = firstNonNull(sourceMetadata.headerValue, match.headerValue());
        sourceMetadata.responseBody = firstNonNull(sourceMetadata.responseBody, match.responseBody());
        sourceMetadata.variables.putIfAbsent(variableName, value);
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

        collectVariableNamesFromParameters(request.path("queryString"), names);
        collectVariableNames(extractQueryPart(request.path("url").asText("")), names);

        JsonNode postDataNode = request.path("postData");
        if (postDataNode instanceof ObjectNode postData) {
            collectVariableNamesFromParameters(postData.path("params"), names);
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
        if (containsVariableTokenInParameters(request.path("queryString"))) {
            return true;
        }
        if (containsVariableToken(extractQueryPart(request.path("url").asText("")))) {
            return true;
        }

        JsonNode postDataNode = request.path("postData");
        if (postDataNode instanceof ObjectNode postData) {
            if (containsVariableTokenInParameters(postData.path("params"))) {
                return true;
            }
            return containsVariableToken(postData.path("text").asText(""));
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
        return decoded.contains("${");
    }

    private void rewriteQueryValues(ObjectNode request, RewriteContext context) {
        rewriteParameterArray(request.path("queryString"), "query_param", context);

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
        request.put("url", base + "?" + rewriteDelimitedAssignments(query, context) + fragment);
    }

    private void rewriteBodyValues(ObjectNode request, RewriteContext context) {
        JsonNode postDataNode = request.path("postData");
        if (!(postDataNode instanceof ObjectNode postData)) {
            return;
        }

        rewriteParameterArray(postData.path("params"), "body_param", context);

        String text = postData.path("text").asText("");
        if (text.isBlank()) {
            return;
        }

        String mimeType = postData.path("mimeType").asText("").toLowerCase(Locale.ROOT);
        if (looksLikeJson(text) || mimeType.contains("json")) {
            try {
                JsonNode json = objectMapper.readTree(text);
                if (json instanceof ObjectNode object) {
                    rewriteJsonObject(object, context);
                    postData.put("text", objectMapper.writeValueAsString(object));
                    return;
                }
                if (json instanceof ArrayNode array) {
                    rewriteJsonArray(array, "body", context);
                    postData.put("text", objectMapper.writeValueAsString(array));
                    return;
                }
            } catch (Exception ignored) {
                // Fallback on form-like body parsing.
            }
        }

        if (text.contains("=")) {
            postData.put("text", rewriteDelimitedAssignments(text, context));
        }
    }

    private void rewriteJsonObject(ObjectNode object, RewriteContext context) {
        List<String> fieldNames = new ArrayList<>();
        object.fieldNames().forEachRemaining(fieldNames::add);

        for (String fieldName : fieldNames) {
            JsonNode child = object.get(fieldName);
            if (child == null || child.isNull()) {
                continue;
            }
            if (child.isValueNode()) {
                String variableName = resolveVariableName(fieldName, child.asText(""), context);
                if (variableName != null) {
                    object.put(fieldName, "${" + variableName + "}");
                }
                continue;
            }
            if (child instanceof ObjectNode nestedObject) {
                rewriteJsonObject(nestedObject, context);
                continue;
            }
            if (child instanceof ArrayNode nestedArray) {
                rewriteJsonArray(nestedArray, fieldName, context);
            }
        }
    }

    private void rewriteJsonArray(ArrayNode array, String nameHint, RewriteContext context) {
        for (int i = 0; i < array.size(); i++) {
            JsonNode child = array.get(i);
            if (child == null || child.isNull()) {
                continue;
            }
            if (child.isValueNode()) {
                String variableName = resolveVariableName(nameHint, child.asText(""), context);
                if (variableName != null) {
                    array.set(i, objectMapper.getNodeFactory().textNode("${" + variableName + "}"));
                }
                continue;
            }
            if (child instanceof ObjectNode nestedObject) {
                rewriteJsonObject(nestedObject, context);
                continue;
            }
            if (child instanceof ArrayNode nestedArray) {
                rewriteJsonArray(nestedArray, nameHint, context);
            }
        }
    }

    private String rewriteDelimitedAssignments(String text, RewriteContext context) {
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
            String variableName = resolveVariableName(name, value, context);

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

    private void rewriteParameterArray(JsonNode paramsNode, String fallbackName, RewriteContext context) {
        if (!(paramsNode instanceof ArrayNode params)) {
            return;
        }
        for (JsonNode paramNode : params) {
            if (!(paramNode instanceof ObjectNode param)) {
                continue;
            }
            String variableName = resolveVariableName(
                    param.path("name").asText(fallbackName),
                    param.path("value").asText(""),
                    context
            );
            if (variableName != null) {
                param.put("value", "${" + variableName + "}");
            }
        }
    }

    private void collectVariableNamesFromParameters(JsonNode paramsNode, Set<String> names) {
        if (!(paramsNode instanceof ArrayNode params)) {
            return;
        }
        for (JsonNode paramNode : params) {
            collectVariableNames(paramNode.path("value").asText(""), names);
        }
    }

    private boolean containsVariableTokenInParameters(JsonNode paramsNode) {
        if (!(paramsNode instanceof ArrayNode params)) {
            return false;
        }
        for (JsonNode paramNode : params) {
            if (containsVariableToken(paramNode.path("value").asText(""))) {
                return true;
            }
        }
        return false;
    }

    private String extractQueryPart(String url) {
        int queryStart = url.indexOf('?');
        if (queryStart < 0) {
            return url;
        }

        int fragmentStart = url.indexOf('#', queryStart + 1);
        if (fragmentStart < 0) {
            return url.substring(queryStart + 1);
        }
        return url.substring(queryStart + 1, fragmentStart);
    }

    private String resolveVariableName(String parameterName, String value, RewriteContext context) {
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

        String existing = context.valueToVariable.get(normalizedValue);
        if (existing != null) {
            return existing;
        }

        SourceMatch sourceMatch = context.sourceSearchIndex.findFirstSourceMatch(parameterName, normalizedValue);
        if (sourceMatch == null) {
            return null;
        }

        String variableName = uniqueVariableName(parameterName, context.usedVariableNames);
        context.usedVariableNames.add(variableName);
        context.valueToVariable.put(normalizedValue, variableName);
        context.variableToSourceMatch.put(variableName, sourceMatch);
        context.variables.put(variableName, normalizedValue);
        return variableName;
    }

    private <T> T firstNonNull(T first, T fallback) {
        return first != null ? first : fallback;
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
        normalized = UNDERSCORE_RUNS.matcher(normalized).replaceAll("_");
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
        return NON_ALNUM_LOWER.matcher(raw).replaceAll("");
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
            if (containsAsciiLetter(segment)) {
                return segment;
            }
        }
        return fallback == null ? path : fallback;
    }

    private boolean containsAsciiLetter(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                return true;
            }
        }
        return false;
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

    private record RewriteContext(
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            SourceMatchFinder.SourceSearchIndex sourceSearchIndex
    ) {
    }

    private static final class SourceMetadata {
        private String variableName;
        private String variableValue;
        private String extractionType;
        private String headerName;
        private String headerValue;
        private String responseBody;
        private final Map<String, String> variables = new LinkedHashMap<>();
    }
}
