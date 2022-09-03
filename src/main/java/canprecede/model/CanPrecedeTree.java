package canprecede.model;

import java.util.ArrayList;

public class CanPrecedeTree {
    private ArrayList<CanPrecedeNode> nodes = new ArrayList<>();

    public ArrayList<CanPrecedeNode> getNodes() {
        return nodes;
    }

    public void setNodes(ArrayList<CanPrecedeNode> nodes) {
        this.nodes = nodes;
    }

    public void setNode(CanPrecedeNode node) {
        this.nodes.add(node);
    }

    @Override
    public String toString() {
        return "CanPrecedeTree{" +
                "nodes=" + nodes +
                '}';
    }

}
