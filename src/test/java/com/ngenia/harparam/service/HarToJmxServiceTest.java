package com.ngenia.harparam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ngenia.harparam.model.AnalysisResult;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author bpabdelkader
 */
class HarToJmxServiceTest {

    private static final String TEST_HAR_RESOURCE = "TestHAR-min.har";

    @Test
    void shouldIncludeRegexExtractorsUnderSourceSampler() throws Exception {
        AnalysisResult result = analyze(TEST_HAR_RESOURCE);

        HarToJmxService service = new HarToJmxService();
        String jmx = service.toJmx(result.rewrittenRequests(), result.variables(), result.regexByVariable());

        assertTrue(jmx.contains("<ThreadGroup guiclass=\"ThreadGroupGui\" testclass=\"ThreadGroup\" testname=\"SC01_01-"));
        assertTrue(!jmx.contains("testname=\"Thread Group\""));
        assertTrue(jmx.contains("<RegexExtractor guiclass=\"RegexExtractorGui\" testclass=\"RegexExtractor\" testname=\"codeh\">"));
        assertTrue(jmx.contains("<stringProp name=\"RegexExtractor.refname\">codeh</stringProp>"));
        assertTrue(jmx.contains("<stringProp name=\"RegexExtractor.regex\">auth\\?codeH=(.+?)&amp;</stringProp>"));
        assertTrue(jmx.contains("<hashTree/>\n          <HeaderManager"));
    }

    private AnalysisResult analyze(String resourceName) throws Exception {
        InputStream input = HarToJmxServiceTest.class.getClassLoader().getResourceAsStream(resourceName);
        assertNotNull(input, "Missing test HAR resource: " + resourceName);

        HarAnalysisService service = new HarAnalysisService(new ObjectMapper());
        MockMultipartFile harFile = new MockMultipartFile(
                "file",
                resourceName,
                "application/json",
                input.readAllBytes()
        );
        return service.analyze(harFile);
    }
}
