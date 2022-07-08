package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;

public class AlternateTerm{
    @JsonProperty("Term")
    public String term;
    @JsonProperty("Description")
    public String description;
}
