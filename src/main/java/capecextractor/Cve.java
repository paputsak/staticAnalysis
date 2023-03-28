package capecextractor;

import java.util.ArrayList;

public class Cve {
    private String cveId;
    private String vulnerabilityDescription;
    private String severityDescription;
    private double cvssScore;
    private String cvssVector;
    private ArrayList<String> vulnerableAsset;
    private ArrayList<String> capecs;

    public Cve() {
    }

    public String getCveId() {
        return cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public String getVulnerabilityDescription() {
        return vulnerabilityDescription;
    }

    public void setVulnerabilityDescription(String vulnerabilityDescription) {
        this.vulnerabilityDescription = vulnerabilityDescription;
    }

    public String getSeverityDescription() {
        return severityDescription;
    }

    public void setSeverityDescription(String severityDescription) {
        this.severityDescription = severityDescription;
    }

    public double getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getCvssVector() {
        return cvssVector;
    }

    public void setCvssVector(String cvssVector) {
        this.cvssVector = cvssVector;
    }

    public ArrayList<String> getVulnerableAsset() {
        return vulnerableAsset;
    }

    public void setVulnerableAsset(ArrayList<String> vulnerableAsset) {
        this.vulnerableAsset = vulnerableAsset;
    }

    public ArrayList<String> getCapecs() {
        return capecs;
    }

    public void setCapecs(ArrayList<String> capecs) {
        this.capecs = capecs;
    }

    @Override
    public String toString() {
        return "Cve{" +
                "cveId='" + cveId + '\'' +
                ", vulnerabilityDescription='" + vulnerabilityDescription + '\'' +
                ", severityDescription='" + severityDescription + '\'' +
                ", cvssScore=" + cvssScore +
                ", cvssVector='" + cvssVector + '\'' +
                ", vulnerableAsset=" + vulnerableAsset +
                ", capecs=" + capecs +
                '}';
    }
}
