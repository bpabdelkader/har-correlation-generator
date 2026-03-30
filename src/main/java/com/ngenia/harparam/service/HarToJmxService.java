package com.ngenia.harparam.service;

import com.ngenia.harparam.model.RewrittenRequest;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

@Service
public class HarToJmxService {

    public String toJmx(List<RewrittenRequest> requests, Map<String, String> variables, Map<String, String> regexByVariable) {
        StringBuilder jmx = new StringBuilder(32_768);
        jmx.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        jmx.append("<jmeterTestPlan version=\"1.2\" properties=\"5.0\" jmeter=\"5.6.3\">\n");
        jmx.append("  <hashTree>\n");
        jmx.append("    <TestPlan guiclass=\"TestPlanGui\" testclass=\"TestPlan\" testname=\"HAR Converted Plan\" enabled=\"true\">\n");
        jmx.append("      <stringProp name=\"TestPlan.comments\"></stringProp>\n");
        jmx.append("      <boolProp name=\"TestPlan.functional_mode\">false</boolProp>\n");
        jmx.append("      <boolProp name=\"TestPlan.tearDown_on_shutdown\">true</boolProp>\n");
        jmx.append("      <boolProp name=\"TestPlan.serialize_threadgroups\">false</boolProp>\n");
        jmx.append("      <elementProp name=\"TestPlan.user_defined_variables\" elementType=\"Arguments\" guiclass=\"ArgumentsPanel\" testclass=\"Arguments\" testname=\"User Variables\" enabled=\"true\">\n");
        jmx.append("        <collectionProp name=\"Arguments.arguments\">\n");
        appendUserVariables(jmx, variables);
        jmx.append("        </collectionProp>\n");
        jmx.append("      </elementProp>\n");
        jmx.append("      <stringProp name=\"TestPlan.user_define_classpath\"></stringProp>\n");
        jmx.append("    </TestPlan>\n");
        jmx.append("    <hashTree>\n");
        appendThreadGroups(jmx, requests == null ? List.of() : requests, regexByVariable == null ? Map.of() : regexByVariable);
        jmx.append("    </hashTree>\n");
        jmx.append("  </hashTree>\n");
        jmx.append("</jmeterTestPlan>\n");
        return jmx.toString();
    }

    private void appendUserVariables(StringBuilder jmx, Map<String, String> variables) {
        if (variables == null || variables.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : variables.entrySet()) {
            String name = Objects.toString(entry.getKey(), "");
            if (name.isBlank()) {
                continue;
            }
            jmx.append("          <elementProp name=\"")
                    .append(xml(name))
                    .append("\" elementType=\"Argument\">\n");
            jmx.append("            <stringProp name=\"Argument.name\">").append(xml(name)).append("</stringProp>\n");
            jmx.append("            <stringProp name=\"Argument.value\">").append(xml(entry.getValue())).append("</stringProp>\n");
            jmx.append("            <stringProp name=\"Argument.metadata\">=</stringProp>\n");
            jmx.append("          </elementProp>\n");
        }
    }

    private void appendSamplers(StringBuilder jmx, List<RewrittenRequest> requests, Map<String, String> regexByVariable) {
        for (RewrittenRequest req : requests) {
            UrlParts url = parseUrl(req.rewrittenUrl());
            Map<String, String> headers = filteredHeaders(req.rewrittenHeaders());
            String method = upper(req.method(), "GET");
            String body = Objects.toString(req.rewrittenBody(), "");
            boolean hasBody = !body.isBlank();
            boolean formBody = hasBody && isFormEncoded(headers);
            boolean rawBody = hasBody && !formBody;

            List<NameValue> queryArgs = parsePairs(url.query());
            List<NameValue> bodyArgs = formBody ? parsePairs(body) : List.of();

            String testName = "R" + req.index() + " " + method + " " + safeName(req.name());

            jmx.append("        <HTTPSamplerProxy guiclass=\"HttpTestSampleGui\" testclass=\"HTTPSamplerProxy\" testname=\"")
                    .append(xml(testName))
                    .append("\" enabled=\"true\">\n");
            jmx.append("          <elementProp name=\"HTTPsampler.Arguments\" elementType=\"Arguments\">\n");
            jmx.append("            <collectionProp name=\"Arguments.arguments\">\n");

            if (rawBody) {
                appendRawBodyArgument(jmx, body);
            } else {
                for (NameValue arg : queryArgs) {
                    appendHttpArgument(jmx, arg.name(), arg.value());
                }
                for (NameValue arg : bodyArgs) {
                    appendHttpArgument(jmx, arg.name(), arg.value());
                }
            }

            jmx.append("            </collectionProp>\n");
            jmx.append("          </elementProp>\n");
            jmx.append("          <stringProp name=\"HTTPSampler.domain\">").append(xml(url.domain())).append("</stringProp>\n");
            jmx.append("          <stringProp name=\"HTTPSampler.port\">").append(xml(url.port())).append("</stringProp>\n");
            jmx.append("          <stringProp name=\"HTTPSampler.protocol\">").append(xml(url.protocol())).append("</stringProp>\n");
            jmx.append("          <stringProp name=\"HTTPSampler.contentEncoding\"></stringProp>\n");
            jmx.append("          <stringProp name=\"HTTPSampler.path\">").append(xml(rawBody ? url.pathWithQuery() : url.path())).append("</stringProp>\n");
            jmx.append("          <stringProp name=\"HTTPSampler.method\">").append(xml(method)).append("</stringProp>\n");
            jmx.append("          <boolProp name=\"HTTPSampler.follow_redirects\">true</boolProp>\n");
            jmx.append("          <boolProp name=\"HTTPSampler.auto_redirects\">false</boolProp>\n");
            jmx.append("          <boolProp name=\"HTTPSampler.use_keepalive\">true</boolProp>\n");
            jmx.append("          <boolProp name=\"HTTPSampler.DO_MULTIPART_POST\">false</boolProp>\n");
            jmx.append("          <stringProp name=\"HTTPSampler.embedded_url_re\"></stringProp>\n");
            jmx.append("          <boolProp name=\"HTTPSampler.postBodyRaw\">").append(rawBody).append("</boolProp>\n");
            jmx.append("        </HTTPSamplerProxy>\n");
            jmx.append("        <hashTree>\n");
            appendRegexExtractors(jmx, req.sourceVariables(), regexByVariable);
            appendHeaderManager(jmx, headers);
            jmx.append("        </hashTree>\n");
        }
    }

    private void appendThreadGroups(StringBuilder jmx, List<RewrittenRequest> requests, Map<String, String> regexByVariable) {
        List<List<RewrittenRequest>> containers = groupRequestsByContainer(requests);
        for (int i = 0; i < containers.size(); i++) {
            List<RewrittenRequest> container = containers.get(i);
            if (container.isEmpty()) {
                continue;
            }
            appendThreadGroup(jmx, container, i + 1, regexByVariable);
        }
    }

    private List<List<RewrittenRequest>> groupRequestsByContainer(List<RewrittenRequest> requests) {
        if (requests == null || requests.isEmpty()) {
            return List.of();
        }

        List<List<RewrittenRequest>> groups = new ArrayList<>();
        List<RewrittenRequest> current = new ArrayList<>();
        long previousTs = Long.MIN_VALUE;

        for (RewrittenRequest request : requests) {
            long ts = parseTimestamp(request.startedDateTime());
            boolean startNew = current.isEmpty();
            if (!startNew) {
                if (ts == Long.MIN_VALUE || previousTs == Long.MIN_VALUE) {
                    startNew = true;
                } else {
                    startNew = (ts - previousTs) >= 1_000L;
                }
            }

            if (startNew) {
                if (!current.isEmpty()) {
                    groups.add(current);
                }
                current = new ArrayList<>();
            }

            current.add(request);
            previousTs = ts;
        }

        if (!current.isEmpty()) {
            groups.add(current);
        }
        return groups;
    }

    private void appendThreadGroup(StringBuilder jmx, List<RewrittenRequest> requests, int groupIndex, Map<String, String> regexByVariable) {
        String threadGroupName = transactionTitleFor(requests.get(0), groupIndex);
        jmx.append("      <ThreadGroup guiclass=\"ThreadGroupGui\" testclass=\"ThreadGroup\" testname=\"")
                .append(xml(threadGroupName))
                .append("\" enabled=\"true\">\n");
        jmx.append("        <stringProp name=\"ThreadGroup.on_sample_error\">continue</stringProp>\n");
        jmx.append("        <elementProp name=\"ThreadGroup.main_controller\" elementType=\"LoopController\" guiclass=\"LoopControlPanel\" testclass=\"LoopController\" testname=\"Loop Controller\" enabled=\"true\">\n");
        jmx.append("          <boolProp name=\"LoopController.continue_forever\">false</boolProp>\n");
        jmx.append("          <stringProp name=\"LoopController.loops\">1</stringProp>\n");
        jmx.append("        </elementProp>\n");
        jmx.append("        <stringProp name=\"ThreadGroup.num_threads\">1</stringProp>\n");
        jmx.append("        <stringProp name=\"ThreadGroup.ramp_time\">1</stringProp>\n");
        jmx.append("        <boolProp name=\"ThreadGroup.scheduler\">false</boolProp>\n");
        jmx.append("        <stringProp name=\"ThreadGroup.duration\"></stringProp>\n");
        jmx.append("        <stringProp name=\"ThreadGroup.delay\"></stringProp>\n");
        jmx.append("      </ThreadGroup>\n");
        jmx.append("      <hashTree>\n");
        appendSamplers(jmx, requests, regexByVariable);
        jmx.append("      </hashTree>\n");
    }

    private void appendRegexExtractors(StringBuilder jmx, Map<String, String> sourceVariables, Map<String, String> regexByVariable) {
        if (sourceVariables == null || sourceVariables.isEmpty() || regexByVariable == null || regexByVariable.isEmpty()) {
            return;
        }

        for (String variableName : sourceVariables.keySet()) {
            String name = Objects.toString(variableName, "");
            String regex = regexByVariable.get(name);
            if (name.isBlank() || regex == null || regex.isBlank()) {
                continue;
            }
            jmx.append("          <RegexExtractor guiclass=\"RegexExtractorGui\" testclass=\"RegexExtractor\" testname=\"")
                    .append(xml(name))
                    .append("\">\n");
            jmx.append("            <stringProp name=\"RegexExtractor.useHeaders\">false</stringProp>\n");
            jmx.append("            <stringProp name=\"RegexExtractor.refname\">").append(xml(name)).append("</stringProp>\n");
            jmx.append("            <stringProp name=\"RegexExtractor.regex\">").append(xml(regex)).append("</stringProp>\n");
            jmx.append("            <stringProp name=\"RegexExtractor.template\">$1$</stringProp>\n");
            jmx.append("            <stringProp name=\"RegexExtractor.default\">NotFound</stringProp>\n");
            jmx.append("            <stringProp name=\"RegexExtractor.match_number\">1</stringProp>\n");
            jmx.append("            <boolProp name=\"RegexExtractor.default_empty_value\">false</boolProp>\n");
            jmx.append("          </RegexExtractor>\n");
            jmx.append("          <hashTree/>\n");
        }
    }

    private void appendRawBodyArgument(StringBuilder jmx, String body) {
        jmx.append("              <elementProp name=\"\" elementType=\"HTTPArgument\">\n");
        jmx.append("                <boolProp name=\"HTTPArgument.always_encode\">false</boolProp>\n");
        jmx.append("                <stringProp name=\"Argument.name\"></stringProp>\n");
        jmx.append("                <stringProp name=\"Argument.value\">").append(xml(body)).append("</stringProp>\n");
        jmx.append("                <stringProp name=\"Argument.metadata\">=</stringProp>\n");
        jmx.append("                <boolProp name=\"HTTPArgument.use_equals\">false</boolProp>\n");
        jmx.append("              </elementProp>\n");
    }

    private void appendHttpArgument(StringBuilder jmx, String name, String value) {
        jmx.append("              <elementProp name=\"").append(xml(name)).append("\" elementType=\"HTTPArgument\">\n");
        jmx.append("                <boolProp name=\"HTTPArgument.always_encode\">false</boolProp>\n");
        jmx.append("                <stringProp name=\"Argument.name\">").append(xml(name)).append("</stringProp>\n");
        jmx.append("                <stringProp name=\"Argument.value\">").append(xml(value)).append("</stringProp>\n");
        jmx.append("                <stringProp name=\"Argument.metadata\">=</stringProp>\n");
        jmx.append("                <boolProp name=\"HTTPArgument.use_equals\">true</boolProp>\n");
        jmx.append("              </elementProp>\n");
    }

    private void appendHeaderManager(StringBuilder jmx, Map<String, String> headers) {
        if (headers.isEmpty()) {
            jmx.append("          <HeaderManager guiclass=\"HeaderPanel\" testclass=\"HeaderManager\" testname=\"HTTP Header Manager\" enabled=\"true\">\n");
            jmx.append("            <collectionProp name=\"HeaderManager.headers\"></collectionProp>\n");
            jmx.append("          </HeaderManager>\n");
            jmx.append("          <hashTree/>\n");
            return;
        }

        jmx.append("          <HeaderManager guiclass=\"HeaderPanel\" testclass=\"HeaderManager\" testname=\"HTTP Header Manager\" enabled=\"true\">\n");
        jmx.append("            <collectionProp name=\"HeaderManager.headers\">\n");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            jmx.append("              <elementProp name=\"\" elementType=\"Header\">\n");
            jmx.append("                <stringProp name=\"Header.name\">").append(xml(header.getKey())).append("</stringProp>\n");
            jmx.append("                <stringProp name=\"Header.value\">").append(xml(header.getValue())).append("</stringProp>\n");
            jmx.append("              </elementProp>\n");
        }
        jmx.append("            </collectionProp>\n");
        jmx.append("          </HeaderManager>\n");
        jmx.append("          <hashTree/>\n");
    }

    private Map<String, String> filteredHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return Map.of();
        }
        Map<String, String> cleaned = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String name = Objects.toString(entry.getKey(), "");
            String value = Objects.toString(entry.getValue(), "");
            if (name.isBlank() || value.isBlank()) {
                continue;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            if ("content-length".equals(lower) || "host".equals(lower)) {
                continue;
            }
            cleaned.put(name, value);
        }
        return cleaned;
    }

    private boolean isFormEncoded(Map<String, String> headers) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (!"content-type".equalsIgnoreCase(entry.getKey())) {
                continue;
            }
            String value = Objects.toString(entry.getValue(), "").toLowerCase(Locale.ROOT);
            if (value.contains("application/x-www-form-urlencoded")) {
                return true;
            }
        }
        return false;
    }

    private List<NameValue> parsePairs(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        String[] pairs = text.split("&");
        List<NameValue> out = new ArrayList<>(pairs.length);
        for (String pair : pairs) {
            String[] split = pair.split("=", 2);
            String name = split.length > 0 ? split[0] : "";
            String value = split.length > 1 ? split[1] : "";
            out.add(new NameValue(name, value));
        }
        return out;
    }

    private UrlParts parseUrl(String rawUrl) {
        String url = Objects.toString(rawUrl, "").trim();
        if (url.isBlank()) {
            return new UrlParts("https", "", "", "/", "", "/");
        }

        String protocol = "https";
        String remainder = url;
        if (url.startsWith("http://")) {
            protocol = "http";
            remainder = url.substring("http://".length());
        } else if (url.startsWith("https://")) {
            protocol = "https";
            remainder = url.substring("https://".length());
        }

        int slashIndex = remainder.indexOf('/');
        int questionIndex = remainder.indexOf('?');
        int splitIndex;
        if (slashIndex < 0) {
            splitIndex = questionIndex;
        } else if (questionIndex < 0) {
            splitIndex = slashIndex;
        } else {
            splitIndex = Math.min(slashIndex, questionIndex);
        }
        if (splitIndex < 0) {
            splitIndex = remainder.length();
        }

        String hostPort = remainder.substring(0, splitIndex);
        String pathAndQuery = splitIndex < remainder.length() ? remainder.substring(splitIndex) : "/";
        if (pathAndQuery.isBlank()) {
            pathAndQuery = "/";
        }
        if (!pathAndQuery.startsWith("/")) {
            pathAndQuery = "/" + pathAndQuery;
        }

        String domain = hostPort;
        String port = "";
        int colon = hostPort.lastIndexOf(':');
        if (colon > 0 && colon + 1 < hostPort.length()) {
            String candidatePort = hostPort.substring(colon + 1);
            if (candidatePort.matches("\\d+")) {
                domain = hostPort.substring(0, colon);
                port = candidatePort;
            }
        }

        String path = pathAndQuery;
        String query = "";
        int hashIdx = path.indexOf('#');
        if (hashIdx >= 0) {
            path = path.substring(0, hashIdx);
        }
        int q = path.indexOf('?');
        if (q >= 0) {
            query = path.substring(q + 1);
            path = path.substring(0, q);
        }
        if (path.isBlank()) {
            path = "/";
        }
        String pathWithQuery = query.isBlank() ? path : path + "?" + query;
        return new UrlParts(protocol, domain, port, path, query, pathWithQuery);
    }

    private String upper(String value, String fallback) {
        String text = Objects.toString(value, "").trim();
        return text.isBlank() ? fallback : text.toUpperCase(Locale.ROOT);
    }

    private String safeName(String name) {
        String text = Objects.toString(name, "").trim();
        return text.isBlank() ? "/" : text;
    }

    private long parseTimestamp(String raw) {
        String text = Objects.toString(raw, "").trim();
        if (text.isBlank()) {
            return Long.MIN_VALUE;
        }
        try {
            return OffsetDateTime.parse(text).toInstant().toEpochMilli();
        } catch (Exception e) {
            return Long.MIN_VALUE;
        }
    }

    private String transactionTitleFor(RewrittenRequest request, int fallbackIndex) {
        return "SC01_" + pad2(fallbackIndex) + "-" + normalizeTransactionLabel(request == null ? "" : request.name());
    }

    private String pad2(int value) {
        return value < 10 ? "0" + value : Integer.toString(value);
    }

    private String normalizeTransactionLabel(String raw) {
        String text = Objects.toString(raw, "").trim();
        if (text.isBlank() || "/".equals(text)) {
            return "Home";
        }

        text = text.replaceAll("[_\\s]+", "-");
        text = text.replaceAll("[^A-Za-z0-9-]+", "-");
        text = text.replaceAll("-+", "-");
        text = text.replaceAll("^-|-$", "");
        if (text.isBlank()) {
            return "Home";
        }

        return Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }

    private String xml(String text) {
        String input = stripIllegalXmlChars(Objects.toString(text, ""));
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    private String stripIllegalXmlChars(String input) {
        if (input.isEmpty()) {
            return input;
        }

        StringBuilder cleaned = new StringBuilder(input.length());
        input.codePoints().forEach(cp -> {
            boolean allowed =
                    cp == 0x9
                            || cp == 0xA
                            || cp == 0xD
                            || (cp >= 0x20 && cp <= 0xD7FF)
                            || (cp >= 0xE000 && cp <= 0xFFFD)
                            || (cp >= 0x10000 && cp <= 0x10FFFF);
            if (allowed) {
                cleaned.appendCodePoint(cp);
            }
        });
        return cleaned.toString();
    }

    private record UrlParts(
            String protocol,
            String domain,
            String port,
            String path,
            String query,
            String pathWithQuery
    ) {
    }

    private record NameValue(String name, String value) {
    }
}
