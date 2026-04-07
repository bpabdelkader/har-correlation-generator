package com.ngenia.harparam.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ngenia.harparam.model.AnalysisResult;
import com.ngenia.harparam.service.HarAnalysisService;
import com.ngenia.harparam.service.HarToJmxService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * @author bpabdelkader
 */
@Controller
@Validated
public class HarController {

    private static final String SESSION_MODIFIED_HAR = "modifiedHar";
    private static final String SESSION_ANALYSIS_RESULT = "analysisResult";
    private static final String SESSION_ORIGINAL_HAR_FILENAME = "originalHarFilename";
    private static final String INDEX_VIEW = "index";

    private final HarAnalysisService harAnalysisService;
    private final HarToJmxService harToJmxService;
    private final ObjectMapper objectMapper;
    private final String appVersion;

    public HarController(
            HarAnalysisService harAnalysisService,
            HarToJmxService harToJmxService,
            ObjectMapper objectMapper,
            @Value("${app.version:dev}") String appVersion
    ) {
        this.harAnalysisService = harAnalysisService;
        this.harToJmxService = harToJmxService;
        this.objectMapper = objectMapper;
        this.appVersion = appVersion;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("appVersion", appVersion);
        return INDEX_VIEW;
    }

    @PostMapping("/analyze")
    public String analyze(@RequestParam("harFile") @NotNull MultipartFile harFile, Model model, HttpSession session) {
        if (harFile.isEmpty()) {
            model.addAttribute("error", "The HAR file is empty.");
            return INDEX_VIEW;
        }

        try {
            AnalysisResult result = harAnalysisService.analyze(harFile);
            session.setAttribute(SESSION_MODIFIED_HAR, result.modifiedHarJson().getBytes(StandardCharsets.UTF_8));
            session.setAttribute(SESSION_ANALYSIS_RESULT, result);
            session.setAttribute(SESSION_ORIGINAL_HAR_FILENAME, safeFilename(harFile.getOriginalFilename()));
            return "redirect:/result";
        } catch (Exception e) {
            model.addAttribute("error", "Error while processing HAR: " + e.getMessage());
            return INDEX_VIEW;
        }
    }

    @GetMapping("/result")
    public String result(Model model, HttpSession session) {
        Object stored = session.getAttribute(SESSION_ANALYSIS_RESULT);
        if (!(stored instanceof AnalysisResult result)) {
            return "redirect:/";
        }
        model.addAttribute("result", result);
        model.addAttribute("appVersion", appVersion);
        return "result";
    }

    @GetMapping("/download/har")
    @ResponseBody
    public ResponseEntity<byte[]> downloadHar(HttpSession session) {
        byte[] bytes = requiredSessionAttribute(session, SESSION_MODIFIED_HAR, byte[].class, "No modified HAR available.");
        return download(bytes, MediaType.APPLICATION_JSON, buildModifiedFilename(originalSessionFilename(session), "modified.har"));
    }

    @GetMapping("/download/jmx")
    @ResponseBody
    public ResponseEntity<byte[]> downloadJmx(HttpSession session) {
        AnalysisResult result = requiredSessionAttribute(session, SESSION_ANALYSIS_RESULT, AnalysisResult.class, "No analysis result available.");
        String jmx = harToJmxService.toJmx(result.rewrittenRequests(), result.variables(), result.regexByVariable());
        return download(
                jmx.getBytes(StandardCharsets.UTF_8),
                MediaType.APPLICATION_XML,
                buildSiblingFilename(originalSessionFilename(session), ".jmx", "modified.jmx")
        );
    }

    @GetMapping("/download/rules")
    @ResponseBody
    public ResponseEntity<byte[]> downloadRules(HttpSession session) throws Exception {
        AnalysisResult result = requiredSessionAttribute(session, SESSION_ANALYSIS_RESULT, AnalysisResult.class, "No analysis result available.");

        Map<String, String> variables = new LinkedHashMap<>();
        Map<String, String> regexByVariable = result.regexByVariable() == null ? Map.of() : result.regexByVariable();

        for (String name : result.variables().keySet()) {
            if (name == null || name.isBlank()) {
                continue;
            }
            String regex = regexByVariable.get(name);
            if (regex != null && !regex.isBlank()) {
                variables.put(name, regex);
            }
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("variables", variables);

        return download(
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(payload),
                MediaType.APPLICATION_JSON,
                "correlation-rules.json"
        );
    }

    private String safeFilename(String input) {
        String name = input == null ? "" : input.trim();
        if (name.isBlank()) {
            return "";
        }

        name = name.replace('\\', '/');
        int slash = name.lastIndexOf('/');
        if (slash >= 0 && slash + 1 < name.length()) {
            name = name.substring(slash + 1);
        }

        name = name.replace("\"", "").trim();
        if (name.isBlank()) {
            return "";
        }

        return name;
    }

    private String buildModifiedFilename(String original, String fallback) {
        String name = safeFilename(original);
        if (name.isBlank()) {
            return fallback;
        }

        int dot = name.lastIndexOf('.');
        if (dot > 0 && dot < name.length() - 1) {
            String stem = name.substring(0, dot);
            String ext = name.substring(dot);
            return stem + "_modified" + ext;
        }

        return name + "_modified";
    }

    private String buildSiblingFilename(String original, String newExtension, String fallback) {
        String name = safeFilename(original);
        if (name.isBlank()) {
            return fallback;
        }

        int dot = name.lastIndexOf('.');
        if (dot > 0) {
            return name.substring(0, dot) + newExtension;
        }

        return name + newExtension;
    }

    private String originalSessionFilename(HttpSession session) {
        Object stored = session.getAttribute(SESSION_ORIGINAL_HAR_FILENAME);
        return stored instanceof String name && !name.isBlank() ? name : null;
    }

    private <T> T requiredSessionAttribute(HttpSession session, String key, Class<T> type, String message) {
        Object stored = session.getAttribute(key);
        if (type.isInstance(stored)) {
            return type.cast(stored);
        }
        throw new ResponseStatusException(NOT_FOUND, message);
    }

    private ResponseEntity<byte[]> download(byte[] bytes, MediaType mediaType, String filename) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(mediaType);
        headers.setContentDisposition(ContentDisposition.attachment().filename(filename, StandardCharsets.UTF_8).build());
        return ResponseEntity.ok().headers(headers).body(bytes);
    }
}
