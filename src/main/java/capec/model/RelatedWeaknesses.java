package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

public class RelatedWeaknesses{
    @JsonProperty("Related_Weakness") 
    public ArrayList<RelatedWeakness> related_Weakness;

    public ArrayList<RelatedWeakness> getRelated_Weakness() {
        return related_Weakness;
    }

    public void setRelated_Weakness(ArrayList<RelatedWeakness> related_Weakness) {
        this.related_Weakness = related_Weakness;
    }
}
