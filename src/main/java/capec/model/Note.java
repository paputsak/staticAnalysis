package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Note{
    @JsonProperty("-Type") 
    public String type;
    @JsonProperty("#text") 
    public String text;
}
