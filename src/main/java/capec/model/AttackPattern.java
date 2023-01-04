package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AttackPattern{
    @JsonProperty("-ID") 
    public String iD;
    @JsonProperty("-Name") 
    public String name;
    @JsonProperty("-Abstraction") 
    public String abstraction;
    @JsonProperty("-Status") 
    public String status;
    @JsonProperty("Description") 
    public Object description;
    @JsonProperty("Likelihood_Of_Attack") 
    public String likelihood_Of_Attack;
    @JsonProperty("Typical_Severity") 
    public String typical_Severity;
    @JsonProperty("Related_Attack_Patterns") 
    public RelatedAttackPatterns related_Attack_Patterns;
    @JsonProperty("Execution_Flow") 
    public ExecutionFlow execution_Flow;
    @JsonProperty("Prerequisites") 
    public Prerequisites prerequisites;
    @JsonProperty("Skills_Required") 
    public SkillsRequired skills_Required;
    @JsonProperty("Resources_Required") 
    public ResourcesRequired resources_Required;
    @JsonProperty("Consequences") 
    public Consequences consequences;
    @JsonProperty("Mitigations") 
    public Mitigations mitigations;
    @JsonProperty("Example_Instances") 
    public ExampleInstances example_Instances;
    @JsonProperty("Related_Weaknesses") 
    public RelatedWeaknesses related_Weaknesses;
    @JsonProperty("Taxonomy_Mappings") 
    public TaxonomyMappings taxonomy_Mappings;
    @JsonProperty("Content_History") 
    public ContentHistory content_History;
    @JsonProperty("Extended_Description") 
    public Object extended_Description;
    @JsonProperty("Indicators") 
    public Indicators indicators;
    @JsonProperty("References") 
    public References references;
    @JsonProperty("Notes") 
    public Notes notes;
    @JsonProperty("Alternate_Terms") 
    public AlternateTerms alternate_Terms;

    public Object getDescription() {
        return description;
    }

    public void setDescription(Object description) {
        this.description = description;
    }

    public Mitigations getMitigations() {
        return mitigations;
    }

    public void setMitigations(Mitigations mitigations) {
        this.mitigations = mitigations;
    }
}
