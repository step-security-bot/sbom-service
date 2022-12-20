package org.opensourceway.sbom.model.echarts;

import org.apache.commons.lang3.tuple.Pair;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Graph implements Serializable {
    private static final double VUL_NODE_SIZE = 50.0;

    private static final double DEP_NODE_SIZE = 40.0;

    private static final double PKG_NODE_SIZE = 30.0;

    private static final double TRANSITIVE_PKG_NODE_SIZE = 20.0;

    private static final double VUL_Y_AXIS = -2000.0;

    private static final double DEP_Y_AXIS = -1000.0;

    private static final double PKG_Y_AXIS = 0.0;

    private static final double Y_AXIS_INTERVAL = 1000.0;

    private static final int X_AXIS_SIZE_MULTIPLIER = 15;

    private Set<Node> nodes = new HashSet<>();

    private Set<Edge> edges = new HashSet<>();

    private final Map<Double, Integer> nodeTypeCount = new HashMap<>();

    private final Map<Pair<String, String>, Node> nodeMap = new HashMap<>();

    public Set<Node> getNodes() {
        return nodes;
    }

    public void setNodes(Set<Node> nodes) {
        this.nodes = nodes;
    }

    public Set<Edge> getEdges() {
        return edges;
    }

    public void setEdges(Set<Edge> edges) {
        this.edges = edges;
    }

    public void addNode(Node node) {
        if (!nodes.contains(node)) {
            nodeTypeCount.merge(node.getY(), 1, Integer::sum);
            nodeMap.put(Pair.of(node.getNodeType(), node.getLabel()), node);
        }
        this.nodes.add(node);
    }

    public void addEdge(Edge edge) {
        this.edges.add(edge);
    }

    public Boolean nodeVisited(Node node) {
        return nodes.contains(node);
    }

    private Node createNode(String nodeType, String label, Double y, Double size, String elementId) {
        if (nodeMap.containsKey(Pair.of(nodeType, label))) {
            return nodeMap.get(Pair.of(nodeType, label));
        }
        var node = new Node();
        node.setNodeType(nodeType);
        node.setLabel(label);
        node.setX(calculateX(y, size));
        node.setY(y);
        node.setId(String.valueOf(nodes.size()));
        node.setSize(size);
        node.setElementId(elementId);
        return node;
    }

    private Double calculateX(Double y, Double size) {
        var nodeCount = nodeTypeCount.getOrDefault(y, 0);
        return Math.floor(nodeCount * Math.pow(-1.0, nodeCount) / 2.0) * size * X_AXIS_SIZE_MULTIPLIER;
    }

    public Node createVulNode(String label) {
        return createNode(NodeType.VUL.getType(), label, VUL_Y_AXIS, VUL_NODE_SIZE, null);
    }

    public Node createDepNode(String label, String pkgId) {
        return createNode(NodeType.DEP.getType(), label, DEP_Y_AXIS, DEP_NODE_SIZE, pkgId);
    }

    public Node createPackageNode(String label, String pkgId) {
        return createNode(NodeType.PKG.getType(), label, PKG_Y_AXIS, PKG_NODE_SIZE, pkgId);
    }

    public Node createTransitiveDepNode(String label, Double y, String pkgId) {
        return createNode(NodeType.TRANSITIVE_DEP.getType(), label, y + Y_AXIS_INTERVAL, TRANSITIVE_PKG_NODE_SIZE, pkgId);
    }
}
