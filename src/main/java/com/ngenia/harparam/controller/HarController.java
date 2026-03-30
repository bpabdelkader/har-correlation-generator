package com.ngenia.harparam.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ngenia.harparam.model.AnalysisResult;
import com.ngenia.harparam.service.HarAnalysisService;
import com.ngenia.harparam.service.HarToJmxService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotNull;
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
import java.util.Map;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Controller
@Validated
public class HarController {

    private static final String SESSION_MODIFIED_HAR = "modifiedHar";
    private static final String SESSION_ANALYSIS_RESULT = "analysisResult";
    private static final String SESSION_ORIGINAL_HAR_FILENAME = "originalHarFilename";

    private final HarAnalysisService harAnalysisService;
    private final HarToJmxService harToJmxService;
    private final ObjectMapper objectMapper;

    public HarController(HarAnalysisService harAnalysisService, HarToJmxService harToJmxService, ObjectMapper objectMapper) {
        this.harAnalysisService = harAnalysisService;
        this.harToJmxService = harToJmxService;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/")
    public String index(Model model) {
        return "index";
    }

    @PostMapping("/analyze")
    public String analyze(@RequestParam("harFile") @NotNull MultipartFile harFile, Model model, HttpSession session) {
        if (harFile.isEmpty()) {
            model.addAttribute("error", "The HAR file is empty.");
            return "index";
        }

        try {
            AnalysisResult result = harAnalysisService.analyze(harFile);
            session.setAttribute(SESSION_MODIFIED_HAR, result.modifiedHarJson().getBytes(StandardCharsets.UTF_8));
            session.setAttribute(SESSION_ANALYSIS_RESULT, result);
            session.setAttribute(SESSION_ORIGINAL_HAR_FILENAME, safeFilename(harFile.getOriginalFilename()));
            return "redirect:/result";
        } catch (Exception e) {
            model.addAttribute("error", "Error while processing HAR: " + e.getMessage());
            return "index";
        }
    }

    @GetMapping("/result")
    public String result(Model model, HttpSession session) {
        Object stored = session.getAttribute(SESSION_ANALYSIS_RESULT);
        if (!(stored instanceof AnalysisResult result)) {
            return "redirect:/";
        }
        model.addAttribute("result", result);
        return "result";
    }

    @GetMapping("/download/har")
    @ResponseBody
    public ResponseEntity<byte[]> downloadHar(HttpSession session) {
        Object stored = session.getAttribute(SESSION_MODIFIED_HAR);
        if (!(stored instanceof byte[] bytes)) {
            throw new ResponseStatusException(NOT_FOUND, "No modified HAR available.");
        }

        String originalName = null;
        Object originalStored = session.getAttribute(SESSION_ORIGINAL_HAR_FILENAME);
        if (originalStored instanceof String name && !name.isBlank()) {
            originalName = name;
        }
        String filename = buildModifiedFilename(originalName, "modified.har");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setContentDisposition(ContentDisposition.attachment().filename(filename, StandardCharsets.UTF_8).build());
        return ResponseEntity.ok().headers(headers).body(bytes);
    }

    @GetMapping("/download/jmx")
    @ResponseBody
    public ResponseEntity<byte[]> downloadJmx(HttpSession session) {
        Object stored = session.getAttribute(SESSION_ANALYSIS_RESULT);
        if (!(stored instanceof AnalysisResult result)) {
            throw new ResponseStatusException(NOT_FOUND, "No analysis result available.");
        }

        String jmx = harToJmxService.toJmx(result.rewrittenRequests(), result.variables(), result.regexByVariable());
        byte[] bytes = jmx.getBytes(StandardCharsets.UTF_8);

        String originalName = null;
        Object originalStored = session.getAttribute(SESSION_ORIGINAL_HAR_FILENAME);
        if (originalStored instanceof String name && !name.isBlank()) {
            originalName = name;
        }
        String filename = buildSiblingFilename(originalName, ".jmx", "modified.jmx");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_XML);
        headers.setContentDisposition(ContentDisposition.attachment().filename(filename, StandardCharsets.UTF_8).build());
        return ResponseEntity.ok().headers(headers).body(bytes);
    }

    @GetMapping("/download/rules")
    @ResponseBody
    public ResponseEntity<byte[]> downloadRules(HttpSession session) throws Exception {
        Object stored = session.getAttribute(SESSION_ANALYSIS_RESULT);
        if (!(stored instanceof AnalysisResult result)) {
            throw new ResponseStatusException(NOT_FOUND, "No analysis result available.");
        }

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

        byte[] bytes = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(payload);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setContentDisposition(ContentDisposition.attachment().filename("correlation-rules.json").build());
        return ResponseEntity.ok().headers(headers).body(bytes);
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
}
