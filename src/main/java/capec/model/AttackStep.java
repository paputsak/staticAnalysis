package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
public class AttackStep{
    @JsonProperty("Step") 
    public String step;
    @JsonProperty("Phase") 
    public String phase;
    @JsonProperty("Description") 
    public Object description;
    @JsonProperty("Technique") 
    public Object technique;
}
