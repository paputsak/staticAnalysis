package ode;

public class Failure extends BaseElement {
    private String originType;
    private String failureClass;
    private String failureRate;
    private Boolean isCCF;

    public String getOriginType() {
        return originType;
    }

    public void setOriginType(String originType) {
        this.originType = originType;
    }

    public String getFailureClass() {
        return failureClass;
    }

    public void setFailureClass(String failureClass) {
        this.failureClass = failureClass;
    }

    public String getFailureRate() {
        return failureRate;
    }

    public void setFailureRate(String failureRate) {
        this.failureRate = failureRate;
    }

    public Boolean getCCF() {
        return isCCF;
    }

    public void setCCF(Boolean CCF) {
        isCCF = CCF;
    }
}
