package com.ngenia.harparam.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ngenia.harparam.model.AnalysisResult;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author bpabdelkader
 */
class HarAnalysisServiceTest {

    private static final String TEST_HAR_RESOURCE = "TestHAR-min.har";

    @Test
    void shouldGenerateMinimalRegexesForTestHarMin() throws Exception {
        AnalysisResult result = analyze(TEST_HAR_RESOURCE);

        assertEquals("auth\\?codeH=(.+?)&", result.regexByVariable().get("codeh"));
        assertEquals("cm_id=(.+?)&", result.regexByVariable().get("cm_id"));
        assertEquals("POT_id=(.+?)&", result.regexByVariable().get("pot_id"));
        assertEquals("erz_id=(.+?)", result.regexByVariable().get("erz_id"));
    }

    private AnalysisResult analyze(String resourceName) throws Exception {
        InputStream input = HarAnalysisServiceTest.class.getClassLoader().getResourceAsStream(resourceName);
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
