package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Capec {
    @JsonProperty("Attack_Pattern_Catalog") 
    public AttackPatternCatalog attack_Pattern_Catalog;
}
