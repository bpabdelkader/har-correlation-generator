package com.ngenia.harparam.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ngenia.harparam.model.AnalysisResult;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void shouldExcludePngCssAndJsEntriesFromDisplayedAndModifiedHar() throws Exception {
        AnalysisResult result = analyzeInline("""
                {
                  "log": {
                    "entries": [
                      {
                        "startedDateTime": "2026-04-05T10:00:00.000Z",
                        "request": {
                          "method": "GET",
                          "url": "https://example.com/index.html",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "text/html; charset=utf-8" }
                          ],
                          "content": {
                            "mimeType": "text/html; charset=utf-8",
                            "text": "<html></html>"
                          }
                        }
                      },
                      {
                        "startedDateTime": "2026-04-05T10:00:01.000Z",
                        "request": {
                          "method": "GET",
                          "url": "https://example.com/app.js",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "application/javascript" }
                          ],
                          "content": {
                            "mimeType": "application/javascript",
                            "text": "console.log('x')"
                          }
                        }
                      },
                      {
                        "startedDateTime": "2026-04-05T10:00:02.000Z",
                        "request": {
                          "method": "GET",
                          "url": "https://example.com/site.css",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "text/css" }
                          ],
                          "content": {
                            "mimeType": "text/css",
                            "text": "body{}"
                          }
                        }
                      },
                      {
                        "startedDateTime": "2026-04-05T10:00:03.000Z",
                        "request": {
                          "method": "GET",
                          "url": "https://cdn.jsdelivr.net/gh/aspectran/aspectran-assets@main/assets/js/navigation.js?v=20250923",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "application/javascript" }
                          ],
                          "content": {
                            "mimeType": "application/javascript",
                            "text": "window.nav=true;"
                          }
                        }
                      },
                      {
                        "startedDateTime": "2026-04-05T10:00:03.500Z",
                        "request": {
                          "method": "GET",
                          "url": "https://example.com/logo.png",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "image/png" }
                          ],
                          "content": {
                            "mimeType": "image/png",
                            "text": ""
                          }
                        }
                      },
                      {
                        "startedDateTime": "2026-04-05T10:00:04.000Z",
                        "request": {
                          "method": "GET",
                          "url": "https://example.com/api/data?id=123",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "application/json" }
                          ],
                          "content": {
                            "mimeType": "application/json",
                            "text": "{\\"ok\\":true}"
                          }
                        }
                      }
                    ]
                  }
                }
                """);

        assertEquals(2, result.rewrittenRequests().size());
        assertTrue(result.rewrittenRequests().stream().anyMatch(req -> req.originalUrl().contains("index.html")));
        assertTrue(result.rewrittenRequests().stream().anyMatch(req -> req.originalUrl().contains("/api/data")));
        assertFalse(result.rewrittenRequests().stream().anyMatch(req -> req.originalUrl().contains(".js")));
        assertFalse(result.rewrittenRequests().stream().anyMatch(req -> req.originalUrl().contains(".css")));
        assertFalse(result.rewrittenRequests().stream().anyMatch(req -> req.originalUrl().contains(".png")));
        assertFalse(result.rewrittenRequests().stream().anyMatch(req -> req.originalUrl().contains("cdn.jsdelivr.net")));

        JsonNode modifiedRoot = new ObjectMapper().readTree(result.modifiedHarJson());
        JsonNode entries = modifiedRoot.path("log").path("entries");
        assertEquals(2, entries.size());
        String modifiedHar = result.modifiedHarJson();
        assertFalse(modifiedHar.contains("cdn.jsdelivr.net/gh/aspectran/aspectran-assets@main/assets/js/navigation.js?v=20250923"));
        assertFalse(modifiedHar.contains("app.js"));
        assertFalse(modifiedHar.contains("site.css"));
        assertFalse(modifiedHar.contains("logo.png"));
    }

    @Test
    void shouldReplaceDynamicPathSegmentsUsingDetectedVariableName() throws Exception {
        HarAnalysisService service = new HarAnalysisService(new ObjectMapper());
        AnalysisResult result = analyzeInline(service, """
                {
                  "log": {
                    "entries": [
                      {
                        "startedDateTime": "2026-04-05T10:10:00.000Z",
                        "request": {
                          "method": "GET",
                          "url": "https://jpetstore.aspectran.com/catalog",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "application/json" }
                          ],
                          "content": {
                            "mimeType": "application/json",
                            "text": "{\\"itemId\\":\\"EST-13\\"}"
                          }
                        }
                      },
                      {
                        "startedDateTime": "2026-04-05T10:10:01.000Z",
                        "request": {
                          "method": "GET",
                          "url": "https://jpetstore.aspectran.com/products/RP-LI-02/items/EST-13",
                          "headers": []
                        },
                        "response": {
                          "headers": [
                            { "name": "Content-Type", "value": "text/html; charset=utf-8" }
                          ],
                          "content": {
                            "mimeType": "text/html; charset=utf-8",
                            "text": "<html></html>"
                          }
                        }
                      }
                    ]
                  }
                }
                """);

        assertEquals("EST-13", result.variables().get("itemid"));
        assertFalse(result.variables().containsKey("productid"));
        assertFalse(result.modifiedHarJson().contains("${pathid"));
        assertTrue(result.rewrittenRequests().stream().anyMatch(req ->
                req.rewrittenUrl().contains("/products/RP-LI-02/items/${itemid}")
        ));
        assertTrue(result.rewrittenRequests().stream().anyMatch(req ->
                "EST-13".equals(req.name()) && req.rewrittenUrl().contains("/products/RP-LI-02/items/${itemid}")
        ));
        assertTrue(result.modifiedHarJson().contains("/products/RP-LI-02/items/${itemid}"));

        assertEquals(1, result.pathRewriteSuggestions().size());
        assertEquals("productid", result.pathRewriteSuggestions().get(0).variableName());
        assertEquals("RP-LI-02", result.pathRewriteSuggestions().get(0).value());
        assertTrue(result.pathRewriteSuggestions().get(0).proposedUrl().contains("/products/${productid}/items/${itemid}"));

        AnalysisResult applied = service.applyPathRewriteSuggestions(result, List.of(0));
        assertNotNull(applied);
        assertEquals("RP-LI-02", applied.variables().get("productid"));
        assertTrue(applied.modifiedHarJson().contains("/products/${productid}/items/${itemid}"));
        assertTrue(applied.rewrittenRequests().stream().anyMatch(req ->
                req.rewrittenUrl().contains("/products/${productid}/items/${itemid}")
        ));
        assertTrue(applied.pathRewriteSuggestions().isEmpty());
    }

    private AnalysisResult analyze(String resourceName) throws Exception {
        InputStream input = HarAnalysisServiceTest.class.getClassLoader().getResourceAsStream(resourceName);
        assertTrue(input != null, "Missing test HAR resource: " + resourceName);

        HarAnalysisService service = new HarAnalysisService(new ObjectMapper());
        MockMultipartFile harFile = new MockMultipartFile(
                "file",
                resourceName,
                "application/json",
                input.readAllBytes()
        );
        return service.analyze(harFile);
    }

    private AnalysisResult analyzeInline(String harJson) throws Exception {
        return analyzeInline(new HarAnalysisService(new ObjectMapper()), harJson);
    }

    private AnalysisResult analyzeInline(HarAnalysisService service, String harJson) throws Exception {
        MockMultipartFile harFile = new MockMultipartFile(
                "file",
                "inline.har",
                "application/json",
                harJson.getBytes(StandardCharsets.UTF_8)
        );
        return service.analyze(harFile);
    }
}
