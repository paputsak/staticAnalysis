package graph.model;

//{ id: 1, label: "Robot crashes with a person", shape: "box", color: "#f7e39c" },

public class Node {
    private int id;
    private String extendedDescription;
    private String label;
    private String shape;
    private String color;
    private String image = "";

    private int widthConstraint;
    private int heightConstraint;
    private int borderWidth;
    private String font;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getShape() {
        return shape;
    }

    public void setShape(String shape) {
        this.shape = shape;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    public int getWidthConstraint() {
        return widthConstraint;
    }

    public void setWidthConstraint(int widthConstraint) {
        this.widthConstraint = widthConstraint;
    }

    public int getHeightConstraint() {
        return heightConstraint;
    }

    public void setHeightConstraint(int heightConstraint) {
        this.heightConstraint = heightConstraint;
    }

    public int getBorderWidth() {
        return borderWidth;
    }

    public void setBorderWidth(int boarderWidth) {
        this.borderWidth = boarderWidth;
    }

    public String getFont() {
        return font;
    }

    public void setFont(String font) {
        this.font = font;
    }

    public String getExtendedDescription() {
        return extendedDescription;
    }

    public void setExtendedDescription(String extendedDescription) {
        this.extendedDescription = extendedDescription;
    }

    @Override
    public String toString() {
        return "Node{" +
                "id=" + id +
                ", extendedDescription='" + extendedDescription + '\'' +
                ", label='" + label + '\'' +
                ", shape='" + shape + '\'' +
                ", color='" + color + '\'' +
                ", image='" + image + '\'' +
                ", widthConstraint=" + widthConstraint +
                ", heightConstraint=" + heightConstraint +
                ", borderWidth=" + borderWidth +
                ", font='" + font + '\'' +
                '}';
    }
}
