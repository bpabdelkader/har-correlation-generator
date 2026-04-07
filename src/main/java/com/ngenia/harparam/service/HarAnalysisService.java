package com.ngenia.harparam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
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

    private static final String JMETER_TIME_NOW_FUNCTION = "${__time(,)}";
    private static final long MIN_REASONABLE_EPOCH_MS = 946684800000L;
    private static final long MAX_REASONABLE_EPOCH_MS = 4102444800000L;
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
    private final ObjectWriter prettyWriter;

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
        this.prettyWriter = objectMapper.writerWithDefaultPrettyPrinter();
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
        FilteredEntries filteredEntries = filterBusinessEntries(originalEntries, modifiedEntries, allowedHostRoots);
        replaceEntries(modifiedRoot, filteredEntries.modifiedEntries());
        RewriteContext rewriteContext = new RewriteContext(
                valueToVariable,
                variableToSourceMatch,
                variables,
                usedVariableNames,
                sourceSearchIndex
        );

        int count = Math.min(filteredEntries.originalEntries().size(), filteredEntries.modifiedEntries().size());
        for (int i = 0; i < count; i++) {
            JsonNode originalEntryNode = filteredEntries.originalEntries().get(i);
            JsonNode modifiedEntryNode = filteredEntries.modifiedEntries().get(i);
            if (originalEntryNode instanceof ObjectNode originalEntry && modifiedEntryNode instanceof ObjectNode modifiedEntry) {
                JsonNode requestNode = modifiedEntry.path("request");
                if (requestNode instanceof ObjectNode request) {
                    RequestRef sourceRequest = toRequestRef(i + 1, originalEntry.path("request"));
                    rewriteUrlPathValues(i + 1, sourceRequest.name(), sourceRequest.url(), request, rewriteContext);
                    rewriteQueryValues(request, rewriteContext);
                    rewriteBodyValues(request, rewriteContext);
                    sourceSearchIndex.add(sourceMatchFinder.snapshotFromResponse(modifiedEntry.path("response"), sourceRequest));
                }
            }
        }

        ObjectNode variablesWrapper = objectMapper.createObjectNode();
        variablesWrapper.set("variables", objectMapper.valueToTree(variables));

        List<RewrittenRequest> rewrittenRequests = buildRewrittenRequests(
                filteredEntries.originalEntries(),
                filteredEntries.modifiedEntries(),
                variableToSourceMatch,
                variables
        );
        String modifiedHarJson = prettyWriter.writeValueAsString(modifiedRoot);
        Map<String, String> regexByVariable = regexBuilder.buildRegexByVariable(variableToSourceMatch, variables);
        applyJmeterRuntimeVariableOverrides(variables, regexByVariable, variablesWrapper);
        return new AnalysisResult(
                variables,
                regexByVariable,
                prettyWriter.writeValueAsString(variablesWrapper),
                modifiedHarJson,
                rewrittenRequests,
                List.of()
        );
    }

    private List<RewrittenRequest> buildRewrittenRequests(
            ArrayNode originalEntries,
            ArrayNode modifiedEntries,
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
            if (!containsVariableizedArgument(modifiedRequest)) {
                continue;
            }

            String method = modifiedRequest.path("method").asText("");
            String rewrittenUrl = modifiedRequest.path("url").asText("");
            String originalUrl = originalRequest.path("url").asText("");
            String name = deriveRequestName(originalUrl);
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
                if (match == null) {
                    continue;
                }
                requestVariables.putIfAbsent(variableName, value);

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
        collectVariableNames(request.path("url").asText(""), names);

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
            String token = direct.group(1);
            if (!isJmeterFunctionExpression("${" + token + "}")) {
                target.add(token);
            }
        }

        String decoded = decode(text);
        Matcher decodedMatcher = VAR_TOKEN.matcher(decoded);
        while (decodedMatcher.find()) {
            String token = decodedMatcher.group(1);
            if (!isJmeterFunctionExpression("${" + token + "}")) {
                target.add(token);
            }
        }
    }

    private boolean containsVariableizedArgument(ObjectNode request) {
        if (containsVariableTokenInParameters(request.path("queryString"))) {
            return true;
        }
        if (containsVariableToken(request.path("url").asText(""))) {
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

    private void rewriteUrlPathValues(int requestIndex, String requestName, String originalUrl, ObjectNode request, RewriteContext context) {
        String url = request.path("url").asText("");
        if (url.isBlank()) {
            return;
        }

        int fragmentStart = url.indexOf('#');
        String fragment = fragmentStart >= 0 ? url.substring(fragmentStart) : "";
        String withoutFragment = fragmentStart >= 0 ? url.substring(0, fragmentStart) : url;

        int queryStart = withoutFragment.indexOf('?');
        String query = queryStart >= 0 ? withoutFragment.substring(queryStart) : "";
        String base = queryStart >= 0 ? withoutFragment.substring(0, queryStart) : withoutFragment;

        int scheme = base.indexOf("://");
        int pathStart = scheme >= 0 ? base.indexOf('/', scheme + 3) : base.indexOf('/');
        if (pathStart < 0 || pathStart >= base.length()) {
            return;
        }

        String prefix = base.substring(0, pathStart);
        String path = base.substring(pathStart);
        String rewrittenPath = rewritePathSegments(requestIndex, requestName, originalUrl, prefix, path, query, fragment, context);
        request.put("url", prefix + rewrittenPath + query + fragment);
    }

    private String rewritePathSegments(
            int requestIndex,
            String requestName,
            String originalUrl,
            String urlPrefix,
            String path,
            String query,
            String fragment,
            RewriteContext context
    ) {
        String[] segments = path.split("/", -1);
        String previousLiteralSegment = null;
        for (int i = 0; i < segments.length; i++) {
            String rawSegment = segments[i];
            if (rawSegment == null || rawSegment.isBlank()) {
                continue;
            }

            String decodedSegment = decode(rawSegment).trim();
            if (decodedSegment.isBlank() || decodedSegment.contains("${")) {
                if (!decodedSegment.isBlank()) {
                    previousLiteralSegment = decodedSegment;
                }
                continue;
            }

            if (!looksLikePathVariableCandidate(decodedSegment)) {
                previousLiteralSegment = decodedSegment;
                continue;
            }

            String variableHint = derivePathVariableHint(previousLiteralSegment, decodedSegment);
            String variableName = resolvePathVariableName(variableHint, decodedSegment, context);
            if (variableName != null) {
                segments[i] = "${" + variableName + "}";
                continue;
            }

            previousLiteralSegment = decodedSegment;
        }

        return String.join("/", segments);
    }

    private String resolvePathVariableName(String parameterName, String value, RewriteContext context) {
        String existing = context.valueToVariable().get(value);
        if (existing != null && !existing.isBlank()) {
            return existing;
        }

        SourceMatch sourceMatch = context.sourceSearchIndex().findFirstSourceMatch(parameterName, value);
        if (sourceMatch == null || sourceMatch.parameterName() == null || sourceMatch.parameterName().isBlank()) {
            return null;
        }

        String normalizedHint = normalizeParameterName(parameterName);
        String normalizedMatch = normalizeParameterName(sourceMatch.parameterName());
        if (normalizedHint.isBlank() || !normalizedHint.equals(normalizedMatch)) {
            return null;
        }

        String variableName = uniqueVariableName(parameterName, context.usedVariableNames());
        context.usedVariableNames().add(variableName);
        context.valueToVariable().put(value, variableName);
        context.variableToSourceMatch().put(variableName, sourceMatch);
        context.variables().put(variableName, value);
        return variableName;
    }

    private String derivePathVariableHint(String previousSegment, String currentSegment) {
        String normalizedPrevious = normalizeParameterName(previousSegment);
        if (!normalizedPrevious.isBlank()) {
            if (normalizedPrevious.endsWith("ies") && normalizedPrevious.length() > 3) {
                return normalizedPrevious.substring(0, normalizedPrevious.length() - 3) + "yid";
            }
            if (normalizedPrevious.endsWith("s") && normalizedPrevious.length() > 1) {
                return normalizedPrevious.substring(0, normalizedPrevious.length() - 1) + "id";
            }
            return normalizedPrevious + "id";
        }
        return isLikelyIdentifier(currentSegment) ? "pathid" : "pathsegment";
    }

    private boolean isLikelyIdentifier(String value) {
        String text = Objects.toString(value, "").trim();
        if (text.isBlank() || text.length() < 2) {
            return false;
        }
        boolean hasDigit = false;
        boolean hasLetter = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (Character.isLetter(c)) {
                hasLetter = true;
            }
        }
        return hasDigit || hasLetter;
    }

    private boolean looksLikePathVariableCandidate(String value) {
        String text = Objects.toString(value, "").trim();
        if (text.isBlank() || text.contains("${")) {
            return false;
        }
        if (!isLikelyIdentifier(text)) {
            return false;
        }
        return text.contains("-") || text.contains("_") || text.chars().anyMatch(Character::isDigit);
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
        for (Iterator<Map.Entry<String, JsonNode>> it = object.fields(); it.hasNext(); ) {
            Map.Entry<String, JsonNode> field = it.next();
            String fieldName = field.getKey();
            JsonNode child = field.getValue();
            if (child == null || child.isNull()) {
                continue;
            }
            if (child.isValueNode()) {
                String replacement = resolveVariableName(fieldName, child.asText(""), context);
                if (replacement != null) {
                    object.put(fieldName, replacementValue(replacement));
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
                String replacement = resolveVariableName(nameHint, child.asText(""), context);
                if (replacement != null) {
                    array.set(i, objectMapper.getNodeFactory().textNode(replacementValue(replacement)));
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
        StringBuilder rewritten = new StringBuilder(text.length() + 16);
        int pairStart = 0;
        int pairIndex = 0;
        while (pairStart <= text.length()) {
            if (pairIndex > 0) {
                rewritten.append('&');
            }

            int amp = text.indexOf('&', pairStart);
            int pairEnd = amp >= 0 ? amp : text.length();
            String pair = text.substring(pairStart, pairEnd);
            if (pair.isBlank()) {
                rewritten.append(pair);
            } else {
                int eq = pair.indexOf('=');
                String rawName = eq >= 0 ? pair.substring(0, eq) : pair;
                String rawValue = eq >= 0 ? pair.substring(eq + 1) : "";
                String name = decode(rawName);
                String value = decode(rawValue);
                String replacement = resolveVariableName(name, value, context);

                rewritten.append(rawName);
                if (eq >= 0) {
                    rewritten.append('=');
                    if (replacement != null) {
                        rewritten.append(replacementValue(replacement));
                    } else {
                        rewritten.append(rawValue);
                    }
                } else {
                    rewritten.append(rawValue);
                }
            }
            if (amp < 0) {
                break;
            }
            pairStart = amp + 1;
            pairIndex++;
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
            String replacement = resolveVariableName(
                    param.path("name").asText(fallbackName),
                    param.path("value").asText(""),
                    context
            );
            if (replacement != null) {
                param.put("value", replacementValue(replacement));
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

        if (isEpochMillisTimestamp(normalizedValue)) {
            return JMETER_TIME_NOW_FUNCTION;
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

    private String replacementValue(String replacement) {
        return isJmeterFunctionExpression(replacement) ? replacement : "${" + replacement + "}";
    }

    private boolean isJmeterFunctionExpression(String value) {
        String text = Objects.toString(value, "").trim();
        return text.startsWith("${__") && text.endsWith("}");
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
        if (value == null || (value.indexOf('%') < 0 && value.indexOf('+') < 0)) {
            return value;
        }
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

    private void applyJmeterRuntimeVariableOverrides(
            Map<String, String> variables,
            Map<String, String> regexByVariable,
            ObjectNode variablesWrapper
    ) {
        if (variables == null || variables.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            String variableName = entry.getKey();
            String override = jmeterRuntimeValueFor(entry.getValue());
            if (override == null) {
                continue;
            }
            entry.setValue(override);
            if (regexByVariable != null) {
                regexByVariable.remove(variableName);
            }
            if (variablesWrapper != null && variablesWrapper.path("variables") instanceof ObjectNode variableObject) {
                variableObject.put(variableName, override);
            }
        }
    }

    private String jmeterRuntimeValueFor(String value) {
        if (isEpochMillisTimestamp(value)) {
            return JMETER_TIME_NOW_FUNCTION;
        }
        return null;
    }

    private boolean isEpochMillisTimestamp(String value) {
        String text = Objects.toString(value, "").trim();
        if (text.length() != 13) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            if (!Character.isDigit(text.charAt(i))) {
                return false;
            }
        }
        try {
            long epochMs = Long.parseLong(text);
            return epochMs >= MIN_REASONABLE_EPOCH_MS && epochMs <= MAX_REASONABLE_EPOCH_MS;
        } catch (NumberFormatException e) {
            return false;
        }
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

    private FilteredEntries filterBusinessEntries(ArrayNode originalEntries, ArrayNode modifiedEntries, Set<String> allowedHostRoots) {
        ArrayNode filteredOriginalEntries = objectMapper.createArrayNode();
        ArrayNode filteredModifiedEntries = objectMapper.createArrayNode();

        int count = Math.min(originalEntries.size(), modifiedEntries.size());
        for (int i = 0; i < count; i++) {
            JsonNode originalEntryNode = originalEntries.get(i);
            JsonNode modifiedEntryNode = modifiedEntries.get(i);
            JsonNode originalRequestNode = originalEntryNode.path("request");
            if (!(originalRequestNode instanceof ObjectNode originalRequest)) {
                continue;
            }
            if (!requestClassifier.isBusinessRequest(originalRequest, originalEntryNode.path("response"), allowedHostRoots)) {
                continue;
            }
            filteredOriginalEntries.add(originalEntryNode);
            filteredModifiedEntries.add(modifiedEntryNode);
        }

        return new FilteredEntries(filteredOriginalEntries, filteredModifiedEntries);
    }

    private void replaceEntries(ObjectNode root, ArrayNode entries) {
        JsonNode logNode = root.path("log");
        if (logNode instanceof ObjectNode logObject) {
            logObject.set("entries", entries);
        }
    }

    private record RewriteContext(
            Map<String, String> valueToVariable,
            Map<String, SourceMatch> variableToSourceMatch,
            Map<String, String> variables,
            Set<String> usedVariableNames,
            SourceMatchFinder.SourceSearchIndex sourceSearchIndex
    ) {
    }

    private record FilteredEntries(ArrayNode originalEntries, ArrayNode modifiedEntries) {
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
