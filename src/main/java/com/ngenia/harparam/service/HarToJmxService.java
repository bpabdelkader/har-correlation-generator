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
import java.util.regex.Pattern;

/**
 * @author bpabdelkader
 */
@Service
public class HarToJmxService {

    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final Pattern LABEL_SPACES = Pattern.compile("[_\\s]+");
    private static final Pattern LABEL_NON_ALNUM = Pattern.compile("[^A-Za-z0-9-]+");
    private static final Pattern LABEL_DASH_RUNS = Pattern.compile("-+");
    private static final Pattern LABEL_EDGE_DASHES = Pattern.compile("^-|-$");

    public String toJmx(List<RewrittenRequest> requests, Map<String, String> variables, Map<String, String> regexByVariable) {
        StringBuilder jmx = new StringBuilder(32_768);
        line(jmx, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        line(jmx, "<jmeterTestPlan version=\"1.2\" properties=\"5.0\" jmeter=\"5.6.3\">");
        line(jmx, "  <hashTree>");
        line(jmx, "    <TestPlan guiclass=\"TestPlanGui\" testclass=\"TestPlan\" testname=\"HAR Converted Plan\" enabled=\"true\">");
        line(jmx, "      <stringProp name=\"TestPlan.comments\"></stringProp>");
        line(jmx, "      <boolProp name=\"TestPlan.functional_mode\">false</boolProp>");
        line(jmx, "      <boolProp name=\"TestPlan.tearDown_on_shutdown\">true</boolProp>");
        line(jmx, "      <boolProp name=\"TestPlan.serialize_threadgroups\">false</boolProp>");
        line(jmx, "      <elementProp name=\"TestPlan.user_defined_variables\" elementType=\"Arguments\" guiclass=\"ArgumentsPanel\" testclass=\"Arguments\" testname=\"User Variables\" enabled=\"true\">");
        line(jmx, "        <collectionProp name=\"Arguments.arguments\">");
        appendUserVariables(jmx, variables);
        line(jmx, "        </collectionProp>");
        line(jmx, "      </elementProp>");
        line(jmx, "      <stringProp name=\"TestPlan.user_define_classpath\"></stringProp>");
        line(jmx, "    </TestPlan>");
        line(jmx, "    <hashTree>");
        appendThreadGroups(jmx, requests == null ? List.of() : requests, regexByVariable == null ? Map.of() : regexByVariable);
        line(jmx, "    </hashTree>");
        line(jmx, "  </hashTree>");
        line(jmx, "</jmeterTestPlan>");
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
            line(jmx, "          <elementProp name=\"%s\" elementType=\"Argument\">", xml(name));
            line(jmx, "            <stringProp name=\"Argument.name\">%s</stringProp>", xml(name));
            line(jmx, "            <stringProp name=\"Argument.value\">%s</stringProp>", xml(entry.getValue()));
            line(jmx, "            <stringProp name=\"Argument.metadata\">=</stringProp>");
            line(jmx, "          </elementProp>");
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

            line(jmx, "        <HTTPSamplerProxy guiclass=\"HttpTestSampleGui\" testclass=\"HTTPSamplerProxy\" testname=\"%s\" enabled=\"true\">", xml(testName));
            line(jmx, "          <elementProp name=\"HTTPsampler.Arguments\" elementType=\"Arguments\">");
            line(jmx, "            <collectionProp name=\"Arguments.arguments\">");

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

            line(jmx, "            </collectionProp>");
            line(jmx, "          </elementProp>");
            line(jmx, "          <stringProp name=\"HTTPSampler.domain\">%s</stringProp>", xml(url.domain()));
            line(jmx, "          <stringProp name=\"HTTPSampler.port\">%s</stringProp>", xml(url.port()));
            line(jmx, "          <stringProp name=\"HTTPSampler.protocol\">%s</stringProp>", xml(url.protocol()));
            line(jmx, "          <stringProp name=\"HTTPSampler.contentEncoding\"></stringProp>");
            line(jmx, "          <stringProp name=\"HTTPSampler.path\">%s</stringProp>", xml(rawBody ? url.pathWithQuery() : url.path()));
            line(jmx, "          <stringProp name=\"HTTPSampler.method\">%s</stringProp>", xml(method));
            line(jmx, "          <boolProp name=\"HTTPSampler.follow_redirects\">true</boolProp>");
            line(jmx, "          <boolProp name=\"HTTPSampler.auto_redirects\">false</boolProp>");
            line(jmx, "          <boolProp name=\"HTTPSampler.use_keepalive\">true</boolProp>");
            line(jmx, "          <boolProp name=\"HTTPSampler.DO_MULTIPART_POST\">false</boolProp>");
            line(jmx, "          <stringProp name=\"HTTPSampler.embedded_url_re\"></stringProp>");
            line(jmx, "          <boolProp name=\"HTTPSampler.postBodyRaw\">%s</boolProp>", rawBody);
            line(jmx, "        </HTTPSamplerProxy>");
            line(jmx, "        <hashTree>");
            appendRegexExtractors(jmx, req.sourceVariables(), regexByVariable);
            appendHeaderManager(jmx, headers);
            line(jmx, "        </hashTree>");
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
        line(jmx, "      <ThreadGroup guiclass=\"ThreadGroupGui\" testclass=\"ThreadGroup\" testname=\"%s\" enabled=\"true\">", xml(threadGroupName));
        line(jmx, "        <stringProp name=\"ThreadGroup.on_sample_error\">continue</stringProp>");
        line(jmx, "        <elementProp name=\"ThreadGroup.main_controller\" elementType=\"LoopController\" guiclass=\"LoopControlPanel\" testclass=\"LoopController\" testname=\"Loop Controller\" enabled=\"true\">");
        line(jmx, "          <boolProp name=\"LoopController.continue_forever\">false</boolProp>");
        line(jmx, "          <stringProp name=\"LoopController.loops\">1</stringProp>");
        line(jmx, "        </elementProp>");
        line(jmx, "        <stringProp name=\"ThreadGroup.num_threads\">1</stringProp>");
        line(jmx, "        <stringProp name=\"ThreadGroup.ramp_time\">1</stringProp>");
        line(jmx, "        <boolProp name=\"ThreadGroup.scheduler\">false</boolProp>");
        line(jmx, "        <stringProp name=\"ThreadGroup.duration\"></stringProp>");
        line(jmx, "        <stringProp name=\"ThreadGroup.delay\"></stringProp>");
        line(jmx, "      </ThreadGroup>");
        line(jmx, "      <hashTree>");
        appendSamplers(jmx, requests, regexByVariable);
        line(jmx, "      </hashTree>");
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
            line(jmx, "          <RegexExtractor guiclass=\"RegexExtractorGui\" testclass=\"RegexExtractor\" testname=\"%s\">", xml(name));
            line(jmx, "            <stringProp name=\"RegexExtractor.useHeaders\">false</stringProp>");
            line(jmx, "            <stringProp name=\"RegexExtractor.refname\">%s</stringProp>", xml(name));
            line(jmx, "            <stringProp name=\"RegexExtractor.regex\">%s</stringProp>", xml(regex));
            line(jmx, "            <stringProp name=\"RegexExtractor.template\">$1$</stringProp>");
            line(jmx, "            <stringProp name=\"RegexExtractor.default\">NotFound</stringProp>");
            line(jmx, "            <stringProp name=\"RegexExtractor.match_number\">1</stringProp>");
            line(jmx, "            <boolProp name=\"RegexExtractor.default_empty_value\">false</boolProp>");
            line(jmx, "          </RegexExtractor>");
            line(jmx, "          <hashTree/>");
        }
    }

    private void appendRawBodyArgument(StringBuilder jmx, String body) {
        appendArgument(jmx, "", body, false);
    }

    private void appendHttpArgument(StringBuilder jmx, String name, String value) {
        appendArgument(jmx, name, value, true);
    }

    private void appendHeaderManager(StringBuilder jmx, Map<String, String> headers) {
        line(jmx, "          <HeaderManager guiclass=\"HeaderPanel\" testclass=\"HeaderManager\" testname=\"HTTP Header Manager\" enabled=\"true\">");

        if (headers.isEmpty()) {
            line(jmx, "            <collectionProp name=\"HeaderManager.headers\"></collectionProp>");
        } else {
            line(jmx, "            <collectionProp name=\"HeaderManager.headers\">");
            for (Map.Entry<String, String> header : headers.entrySet()) {
                line(jmx, "              <elementProp name=\"\" elementType=\"Header\">");
                line(jmx, "                <stringProp name=\"Header.name\">%s</stringProp>", xml(header.getKey()));
                line(jmx, "                <stringProp name=\"Header.value\">%s</stringProp>", xml(header.getValue()));
                line(jmx, "              </elementProp>");
            }
            line(jmx, "            </collectionProp>");
        }

        line(jmx, "          </HeaderManager>");
        line(jmx, "          <hashTree/>");
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
        String contentType = findHeader(headers, "content-type");
        if (contentType == null) {
            return false;
        }
        return contentType.toLowerCase(Locale.ROOT).contains("application/x-www-form-urlencoded");
    }

    private List<NameValue> parsePairs(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        String[] pairs = text.split("&");
        List<NameValue> out = new ArrayList<>(pairs.length);
        for (String pair : pairs) {
            String[] split = pair.split("=", 2);
            out.add(new NameValue(split[0], split.length > 1 ? split[1] : ""));
        }
        return out;
    }

    private String findHeader(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (name.equalsIgnoreCase(entry.getKey())) {
                return entry.getValue();
            }
        }
        return null;
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
            if (DIGITS.matcher(candidatePort).matches()) {
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

        text = LABEL_SPACES.matcher(text).replaceAll("-");
        text = LABEL_NON_ALNUM.matcher(text).replaceAll("-");
        text = LABEL_DASH_RUNS.matcher(text).replaceAll("-");
        text = LABEL_EDGE_DASHES.matcher(text).replaceAll("");
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

    private void appendArgument(StringBuilder jmx, String name, String value, boolean useEquals) {
        line(jmx, "              <elementProp name=\"%s\" elementType=\"HTTPArgument\">", xml(name));
        line(jmx, "                <boolProp name=\"HTTPArgument.always_encode\">false</boolProp>");
        line(jmx, "                <stringProp name=\"Argument.name\">%s</stringProp>", xml(name));
        line(jmx, "                <stringProp name=\"Argument.value\">%s</stringProp>", xml(value));
        line(jmx, "                <stringProp name=\"Argument.metadata\">=</stringProp>");
        line(jmx, "                <boolProp name=\"HTTPArgument.use_equals\">%s</boolProp>", useEquals);
        line(jmx, "              </elementProp>");
    }

    private void line(StringBuilder out, String template, Object... args) {
        out.append(args.length == 0 ? template : template.formatted(args)).append('\n');
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
