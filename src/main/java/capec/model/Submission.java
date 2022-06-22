package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Submission{
    @JsonProperty("Submission_Name") 
    public String submission_Name;
    @JsonProperty("Submission_Organization") 
    public String submission_Organization;
    @JsonProperty("Submission_Date") 
    public String submission_Date;
}
