package ode;

import java.util.ArrayList;

public class Cause extends BaseElement {
    private String type;
    private ArrayList<Failure> failures;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public ArrayList<Failure> getFailures() {
        return failures;
    }

    public void setFailures(ArrayList<Failure> failures) {
        this.failures = failures;
    }
}
