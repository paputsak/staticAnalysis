package rvd.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Severity {
    @JsonProperty("rvss-score")
    public String rvssScore;
    @JsonProperty("rvss-vector")
    public String rvssVector;
    @JsonProperty("severity-description")
    public String severityDescription;
    @JsonProperty("cvss-score")
    public String cvssScore;
    @JsonProperty("cvss-vector")
    public String cvssVector;
}
