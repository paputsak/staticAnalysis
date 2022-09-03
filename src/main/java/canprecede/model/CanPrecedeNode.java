package canprecede.model;

import java.util.ArrayList;

public class CanPrecedeNode {
    private String data;
    private String parent;
    private ArrayList<String> children = new ArrayList<>();
    private boolean gate = false;
    private String gateType;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getParent() {
        return parent;
    }

    public void setParent(String parent) {
        this.parent = parent;
    }

    public ArrayList<String> getChildren() {
        return children;
    }

    public void setChildren(ArrayList<String> children) {
        this.children = children;
    }

    public void setChild(String child) {
        this.children.add(child);
    }

    public boolean isGate() {
        return gate;
    }

    public void setGate(boolean gate) {
        this.gate = gate;
    }

    public String getGateType() {
        return gateType;
    }

    public void setGateType(String gateType) {
        this.gateType = gateType;
    }

    @Override
    public String toString() {
        return "CanPrecedeNode{" +
                "data='" + data + '\'' +
                ", parent='" + parent + '\'' +
                ", children=" + children +
                ", gate=" + gate +
                ", gateType='" + gateType + '\'' +
                '}';
    }
}
