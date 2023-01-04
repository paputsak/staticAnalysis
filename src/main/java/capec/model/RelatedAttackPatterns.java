package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

import java.util.ArrayList;

public class RelatedAttackPatterns{
    @JsonProperty("Related_Attack_Pattern") 
    public ArrayList<RelatedAttackPattern> related_Attack_Pattern;

    public ArrayList<RelatedAttackPattern> getRelated_Attack_Pattern() {
        return related_Attack_Pattern;
    }

    public void setRelated_Attack_Pattern(ArrayList<RelatedAttackPattern> related_Attack_Pattern) {
        this.related_Attack_Pattern = related_Attack_Pattern;
    }
}
