package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
public class ContentHistory{
    @JsonProperty("Submission") 
    public Submission submission;
    @JsonProperty("Modification") 
    public Object modification;
    @JsonProperty("Previous_Entry_Name") 
    public Object previous_Entry_Name;
}
