package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

public class RelatedWeaknesses{
    @JsonProperty("Related_Weakness") 
    public ArrayList<RelatedWeakness> related_Weakness;
}
