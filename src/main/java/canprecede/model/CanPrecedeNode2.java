package canprecede.model;

import java.util.ArrayList;

public class CanPrecedeNode2 {
    private int id;
    private String data;
    private String extendedDescription;
    private int parentId;
    private ArrayList<CanPrecedeNode2> children = new ArrayList<>();
    public enum Type {CAPEC, STATE, GATE}
    private Type nodeType;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public ArrayList<CanPrecedeNode2> getChildren() {
        return children;
    }

    public void setChildren(ArrayList<CanPrecedeNode2> children) {
        this.children = children;
    }

    public void setChild(CanPrecedeNode2 child) {
        this.children.add(child);
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getParentId() {
        return parentId;
    }

    public void setParentId(int parentId) {
        this.parentId = parentId;
    }

    public Type getNodeType() {
        return nodeType;
    }

    public void setNodeType(Type nodeType) {
        this.nodeType = nodeType;
    }

    public String getExtendedDescription() {
        return extendedDescription;
    }

    public void setExtendedDescription(String extendedDescription) {
        this.extendedDescription = extendedDescription;
    }

    @Override
    public String toString() {
        return "CanPrecedeNode2{" +
                "id=" + id +
                ", data='" + data + '\'' +
                ", extendedDescription='" + extendedDescription + '\'' +
                ", parentId=" + parentId +
                ", children=" + children +
                ", nodeType=" + nodeType +
                '}';
    }
}
