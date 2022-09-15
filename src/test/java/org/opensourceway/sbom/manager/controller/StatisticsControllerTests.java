package org.opensourceway.sbom.manager.controller;

import org.junit.jupiter.api.Test;
import org.opensourceway.sbom.manager.SbomApplicationContextHolder;
import org.opensourceway.sbom.manager.SbomManagerApplication;
import org.opensourceway.sbom.manager.TestConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = {SbomManagerApplication.class, SbomApplicationContextHolder.class})
@AutoConfigureMockMvc
public class StatisticsControllerTests {
    @Autowired
    private MockMvc mockMvc;

    @Test
    public void queryProductStatistics() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductStatistics")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.createTime").value("2022-09-15T14:03:20.000+00:00"))
                .andExpect(jsonPath("$.packageCount").value(1000))
                .andExpect(jsonPath("$.depCount").value(2000))
                .andExpect(jsonPath("$.moduleCount").value(3000))
                .andExpect(jsonPath("$.runtimeDepCount").value(0))
                .andExpect(jsonPath("$.vulCount").value(500))
                .andExpect(jsonPath("$.criticalVulCount").value(70))
                .andExpect(jsonPath("$.highVulCount").value(80))
                .andExpect(jsonPath("$.mediumVulCount").value(90))
                .andExpect(jsonPath("$.lowVulCount").value(100))
                .andExpect(jsonPath("$.noneVulCount").value(110))
                .andExpect(jsonPath("$.unknownVulCount").value(50))
                .andExpect(jsonPath("$.packageWithCriticalVulCount").value(130))
                .andExpect(jsonPath("$.packageWithHighVulCount").value(140))
                .andExpect(jsonPath("$.packageWithMediumVulCount").value(150))
                .andExpect(jsonPath("$.packageWithLowVulCount").value(160))
                .andExpect(jsonPath("$.packageWithNoneVulCount").value(170))
                .andExpect(jsonPath("$.packageWithUnknownVulCount").value(180))
                .andExpect(jsonPath("$.packageWithoutVulCount").value(70))
                .andExpect(jsonPath("$.packageWithLegalLicenseCount").value(200))
                .andExpect(jsonPath("$.packageWithIllegalLicenseCount").value(210))
                .andExpect(jsonPath("$.packageWithoutLicenseCount").value(190))
                .andExpect(jsonPath("$.packageWithMultiLicenseCount").value(100))
                .andExpect(jsonPath("$.licenseDistribution.MIT").value(20));
    }

    @Test
    public void queryProductStatisticsNotExists() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductStatistics")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME + "Error")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().string(containsString("product statistics of mindsporeTestError doesn't exist")));
    }

    @Test
    public void queryProductVulTrend() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductVulTrend")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("startTimestamp", "1663150600000")
                        .param("endTimestamp", "1663250600000")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.length()").value(2))
                .andExpect(jsonPath("$.[0].timestamp").value(1663150600000L))
                .andExpect(jsonPath("$.[0].criticalVulCount").value(7))
                .andExpect(jsonPath("$.[0].highVulCount").value(8))
                .andExpect(jsonPath("$.[0].mediumVulCount").value(9))
                .andExpect(jsonPath("$.[0].lowVulCount").value(10))
                .andExpect(jsonPath("$.[0].noneVulCount").value(11))
                .andExpect(jsonPath("$.[0].unknownVulCount").value(5))
                .andExpect(jsonPath("$.[1].timestamp").value(1663250600000L))
                .andExpect(jsonPath("$.[1].criticalVulCount").value(70))
                .andExpect(jsonPath("$.[1].highVulCount").value(80))
                .andExpect(jsonPath("$.[1].mediumVulCount").value(90))
                .andExpect(jsonPath("$.[1].lowVulCount").value(100))
                .andExpect(jsonPath("$.[1].noneVulCount").value(110))
                .andExpect(jsonPath("$.[1].unknownVulCount").value(50));
    }

    @Test
    public void queryProductVulTrendTimeFilter() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductVulTrend")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME)
                        .param("startTimestamp", "1663150600000")
                        .param("endTimestamp", "1663150600001")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$.[0].timestamp").value(1663150600000L))
                .andExpect(jsonPath("$.[0].criticalVulCount").value(7))
                .andExpect(jsonPath("$.[0].highVulCount").value(8))
                .andExpect(jsonPath("$.[0].mediumVulCount").value(9))
                .andExpect(jsonPath("$.[0].lowVulCount").value(10))
                .andExpect(jsonPath("$.[0].noneVulCount").value(11))
                .andExpect(jsonPath("$.[0].unknownVulCount").value(5));
    }

    @Test
    public void queryProductVulTrendNotExists() throws Exception {
        this.mockMvc
                .perform(get("/sbom-api/queryProductVulTrend")
                        .param("productName", TestConstants.SAMPLE_PRODUCT_NAME + "Error")
                        .param("startTimestamp", "1663150600000")
                        .param("endTimestamp", "1663250600000")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/json"))
                .andExpect(jsonPath("$.length()").value(0));
    }
}
