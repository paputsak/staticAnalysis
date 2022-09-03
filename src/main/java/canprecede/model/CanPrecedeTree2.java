package canprecede.model;

import java.util.ArrayList;

public class CanPrecedeTree2 {
    private ArrayList<CanPrecedeNode2> nodes = new ArrayList<>();

    public ArrayList<CanPrecedeNode2> getNodes() {
        return nodes;
    }

    public void setNodes(ArrayList<CanPrecedeNode2> nodes) {
        this.nodes = nodes;
    }

    public void setNode(CanPrecedeNode2 node) {
        this.nodes.add(node);
    }

    @Override
    public String toString() {
        return "CanPrecedeTree{" +
                "nodes=" + nodes +
                '}';
    }

}
