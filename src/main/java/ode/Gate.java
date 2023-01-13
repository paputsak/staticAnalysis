package ode;

import java.util.ArrayList;

public class Gate extends Cause {
    private String gateType;
    private ArrayList<Cause> causes;

    public String getGateType() {
        return gateType;
    }

    public void setGateType(String gateType) {
        this.gateType = gateType;
    }

    public ArrayList<Cause> getCauses() {
        return causes;
    }

    public void setCauses(ArrayList<Cause> causes) {
        this.causes = causes;
    }
}
