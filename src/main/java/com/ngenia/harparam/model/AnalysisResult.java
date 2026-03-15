package com.ngenia.harparam.model;

import java.util.List;
import java.util.Map;

public record AnalysisResult(
        Map<String, String> variables,
        Map<String, String> regexByVariable,
        String variablesJson,
        String modifiedHarJson,
        List<RewrittenRequest> rewrittenRequests
) {
}