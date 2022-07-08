package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

public class Notes{
    @JsonProperty("Note") 
    public ArrayList<Note> note;
}
