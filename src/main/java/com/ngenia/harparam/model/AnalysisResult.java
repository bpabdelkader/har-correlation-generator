package com.ngenia.harparam.model;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * @author bpabdelkader
 */
public record AnalysisResult(
        Map<String, String> variables,
        Map<String, String> regexByVariable,
        String variablesJson,
        String modifiedHarJson,
        List<RewrittenRequest> rewrittenRequests,
        List<PathRewriteSuggestion> pathRewriteSuggestions
) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;
}
