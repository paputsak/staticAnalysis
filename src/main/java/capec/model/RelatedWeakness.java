package capec.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RelatedWeakness{
    @JsonProperty("-CWE_ID")
    public String cWEID;
    @JsonProperty("-self-closing")
    public String selfClosing;
}