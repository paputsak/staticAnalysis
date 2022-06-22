package rvd.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Flaw{
    public String phase;
    public String specificity;
    @JsonProperty("architectural-location")
    public String architecturalLocation;
    public String application;
    public String subsystem;
    @JsonProperty("package")
    public String mypackage;
    public String languages;
    @JsonProperty("date-detected")
    public String dateDetected;
    @JsonProperty("detected-by")
    public String detectedBy;
    @JsonProperty("detected-by-method")
    public String detectedByMethod;
    @JsonProperty("date-reported")
    public String dateReported;
    @JsonProperty("reported-by")
    public String reportedBy;
    @JsonProperty("reported-by-relationship")
    public String reportedByRelationship;
    public String issue;
    public String reproducibility;
    public String trace;
    public String reproduction;
    @JsonProperty("reproduction-image")
    public String reproductionImage;
}
