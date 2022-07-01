package capec.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RelatedAttackPattern {
    @JsonProperty("-Nature")
    public String nature;
    @JsonProperty("-CAPEC_ID")
    public String cAPECID;
    @JsonProperty("-self-closing")
    public String selfClosing;
}
