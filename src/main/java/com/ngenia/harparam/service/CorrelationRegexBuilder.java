package com.ngenia.harparam.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author bpabdelkader
 */
@Service
class CorrelationRegexBuilder {

    private static final Pattern JSON_STRING_FIELD_PREFIX = Pattern.compile("\"([^\"]{1,80})\"\\s*:\\s*\"");
    private static final String[] URL_PARAM_SEPARATORS = {"?", "&", "\\u0026", "&amp;", "%3F", "%26"};
    private static final String[] URL_PARAM_ASSIGNMENTS = {"=", "\\u003d", "%3D"};
    private static final String[] URL_PARAM_SUFFIXES = {"&", "\\u0026", "&amp;", "#", "\\u0023", "%26", "%23"};

    Map<String, String> buildRegexByVariable(Map<String, SourceMatch> variableToSourceMatch, Map<String, String> variables) {
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
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank() && candidate.contains(needle)) {
                return candidate;
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
                String prefix = buildUrlPrefix(text, separator, normalizedParameterName, assignment);
                int valueStart = start + separator.length() + normalizedParameterName.length() + assignment.length();
                int afterIdx = valueStart + value.length();
                String regex = appendUrlSuffix(text, prefix, afterIdx);
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
            String regex = appendUrlSuffix(text, prefix, afterIdx);
            if (regex != null) {
                return regex;
            }
        }
        return null;
    }

    private String buildUrlPrefix(String text, String separator, String parameterName, String assignment) {
        if ("?".equals(separator)) {
            String lastSegment = lastPathSegment(text);
            if (!lastSegment.isBlank()) {
                return lastSegment + separator + parameterName + assignment;
            }
        }
        return parameterName + assignment;
    }

    private String appendUrlSuffix(String text, String prefix, int afterIdx) {
        StringBuilder regex = new StringBuilder(96);
        regex.append(regexEscapeLiteral(prefix));
        regex.append("(.+?)");

        if (afterIdx >= text.length()) {
            return regex.toString();
        }

        for (String suffix : URL_PARAM_SUFFIXES) {
            if (text.startsWith(suffix, afterIdx)) {
                regex.append(regexEscapeLiteral(suffix));
                return regex.toString();
            }
        }

        return regex.toString();
    }

    private String lastPathSegment(String text) {
        try {
            String path = Objects.toString(URI.create(text).getPath(), "");
            if (path.isBlank()) {
                return "";
            }
            int slash = path.lastIndexOf('/');
            return slash >= 0 ? path.substring(slash + 1) : path;
        } catch (Exception ignored) {
            int q = text.indexOf('?');
            String before = q >= 0 ? text.substring(0, q) : text;
            int slash = before.lastIndexOf('/');
            return (slash < 0 || slash + 1 >= before.length()) ? "" : before.substring(slash + 1);
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

        Matcher matcher = JSON_STRING_FIELD_PREFIX.matcher(text);
        while (matcher.find()) {
            if (matcher.end() == idx) {
                String key = matcher.group(1);
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
}
