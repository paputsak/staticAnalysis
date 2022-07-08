package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;

public class AlternateTerms{
    @JsonProperty("Alternate_Term")
    public ArrayList<AlternateTerm> alternate_Term;

}
