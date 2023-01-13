package ode;

import java.util.ArrayList;

public class FaultTree extends FailureModel {
    private ArrayList<Cause> causes;

    public ArrayList<Cause> getCauses() {
        return causes;
    }

    public void setCauses(ArrayList<Cause> causes) {
        this.causes = causes;
    }
}
