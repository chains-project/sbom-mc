package com.cifre.sap.su.goblinWeaver.weaver.addedValue;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SbomAggregated extends Sbom implements AggregateValue<Set<Map<String, String>>>{

    public SbomAggregated(String nodeId) {
        super(nodeId);
    }

    @Override
    public AddedValueEnum getAddedValueEnum() {
        return AddedValueEnum.SBOM_AGGREGATED;
    }

    @Override
    public void computeValue() {
        super.value = computeAggregatedValue(nodeId, new HashSet<>());
    }

    @Override
    public Set<Map<String, String>> mergeValue(Set<Map<String, String>> computedValue, Set<Map<String, String>> computeAggregatedValue) {
        Set<Map<String, String>> mergedSet = new HashSet<>(computedValue);
        mergedSet.addAll(computeAggregatedValue);
        return mergedSet;
    }

    @Override
    public Set<Map<String, String>> computeMetric(String nodeId) {
        return getSbomLinks(nodeId);
    }

    @Override
    public Set<Map<String, String>> getZeroValue() {
        return new HashSet<>();
    }
}
