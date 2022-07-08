package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
public class AttackPatternCatalog{
    @JsonProperty("-xmlns") 
    public String xmlns;
    @JsonProperty("-xmlns:xsi") 
    public String xmlnsXsi;
    @JsonProperty("-xmlns:capec") 
    public String xmlnsCapec;
    @JsonProperty("-xmlns:xhtml") 
    public String xmlnsXhtml;
    @JsonProperty("-Name") 
    public String name;
    @JsonProperty("-Version") 
    public String version;
    @JsonProperty("-Date") 
    public String date;
    @JsonProperty("-xsi:schemaLocation") 
    public String xsiSchemaLocation;
    @JsonProperty("Attack_Patterns") 
    public AttackPatterns attack_Patterns;
}
