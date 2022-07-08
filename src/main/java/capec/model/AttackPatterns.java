package capec.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

public class AttackPatterns{
    @JsonProperty("Attack_Pattern")
    public ArrayList<AttackPattern> attack_Pattern;
}
