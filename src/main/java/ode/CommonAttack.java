package ode;

import capec.model.RelatedAttackPattern;
import capec.model.RelatedWeakness;
import capec.model.RelatedWeaknesses;

import java.util.ArrayList;

public class CommonAttack extends SecurityViolation {
    private String capecId;
    private String title;
    private String capecDescription;
    private String severity;
    private String type;
    private String likelihood;
    private String mitigation;
    private ArrayList<RelatedAttackPattern> relatedCapecs;
    private ArrayList<RelatedWeakness> relatedCwes;

    public String getCapecId() {
        return capecId;
    }

    public void setCapecId(String capecId) {
        this.capecId = capecId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getCapecDescription() {
        return capecDescription;
    }

    public void setCapecDescription(String capecDescription) {
        this.capecDescription = capecDescription;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getLikelihood() {
        return likelihood;
    }

    public void setLikelihood(String likelihood) {
        this.likelihood = likelihood;
    }

    public String getMitigation() {
        return mitigation;
    }

    public void setMitigation(String mitigation) {
        this.mitigation = mitigation;
    }

    public ArrayList<RelatedAttackPattern> getRelatedCapecs() {
        return relatedCapecs;
    }

    public void setRelatedCapecs(ArrayList<RelatedAttackPattern> relatedCapecs) {
        this.relatedCapecs = relatedCapecs;
    }

    public ArrayList<RelatedWeakness> getRelatedCwes() {
        return relatedCwes;
    }

    public void setRelatedCwes(ArrayList<RelatedWeakness> relatedCwes) {
        this.relatedCwes = relatedCwes;
    }

    @Override
    public String toString() {
        return "CommonAttack{" +
                "capecId='" + capecId + '\'' +
                ", title='" + title + '\'' +
                ", capecDescription='" + capecDescription + '\'' +
                ", severity='" + severity + '\'' +
                ", type='" + type + '\'' +
                ", likelihood='" + likelihood + '\'' +
                ", mitigation='" + mitigation + '\'' +
                ", relatedCapecs=" + relatedCapecs +
                ", relatedCwes=" + relatedCwes +
                '}';
    }
}
