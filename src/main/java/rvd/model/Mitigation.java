package rvd.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Mitigation{
    public String description;
    @JsonProperty("pull-request")
    public String pullRequest;
}
