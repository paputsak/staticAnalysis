package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
public class Reference{
    @JsonProperty("-External_Reference_ID") 
    public String externalReferenceID;
    @JsonProperty("-self-closing") 
    public String selfClosing;
    @JsonProperty("-Section") 
    public String section;
}
