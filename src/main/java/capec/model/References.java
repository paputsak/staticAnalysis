package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

public class References{
    @JsonProperty("Reference") 
    public ArrayList<Reference> reference;
}
