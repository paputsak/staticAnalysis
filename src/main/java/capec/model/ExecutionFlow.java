package capec.model;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;

public class ExecutionFlow{
    @JsonProperty("Attack_Step") 
    public ArrayList<AttackStep> attack_Step;
}
