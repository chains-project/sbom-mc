package com.cifre.sap.su.goblinWeaver.weaver.addedValue;

import com.cifre.sap.su.goblinWeaver.graphEntities.nodes.NodeType;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonDeserialize(using = AddedValueEnumDeserializer.class)
public enum AddedValueEnum {
    CVE,
    CVE_AGGREGATED,
    FRESHNESS,
    FRESHNESS_AGGREGATED,
    POPULARITY_1_YEAR,
    POPULARITY_1_YEAR_AGGREGATED,
    SPEED,
    SBOM,
    SBOM_AGGREGATED;

    public NodeType getTargetNodeType(){
        return switch (this) {
            case CVE, CVE_AGGREGATED, FRESHNESS, FRESHNESS_AGGREGATED, POPULARITY_1_YEAR, POPULARITY_1_YEAR_AGGREGATED, SBOM, SBOM_AGGREGATED -> NodeType.RELEASE;
            case SPEED -> NodeType.ARTIFACT;
        };
    }

    public Class<? extends AddedValue<?>> getAddedValueClass(){
        return switch (this) {
            case CVE -> Cve.class;
            case CVE_AGGREGATED -> CveAggregated.class;
            case FRESHNESS -> Freshness.class;
            case FRESHNESS_AGGREGATED -> FreshnessAggregated.class;
            case POPULARITY_1_YEAR -> Popularity1Year.class;
            case POPULARITY_1_YEAR_AGGREGATED -> Popularity1YearAggregated.class;
            case SPEED -> Speed.class;
            case SBOM -> Sbom.class;
            case SBOM_AGGREGATED -> SbomAggregated.class;
        };
    }

    public boolean isAggregatedValue(){
        return switch (this) {
            case CVE_AGGREGATED, FRESHNESS_AGGREGATED, POPULARITY_1_YEAR_AGGREGATED, SBOM_AGGREGATED -> true;
            default -> false;
        };
    }

    public String getJsonKey(){
        return this.name().toLowerCase();
    }
}
