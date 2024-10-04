package com.cifre.sap.su.goblinWeaver.weaver.addedValue;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * The add something here
 */
public class Sbom implements AggregateValue<Set<Map<String, String>>>{

    private final OkHttpClient httpConnector;
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public Sbom() {
        httpConnector = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(120, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS).build();
    }

    /**
     * Get the Maven source jar links for the old and new dependency releases if they exist.
     */
    public List<String> getMavenSourceLinks(String gav) {
        String[] splitedGav = gav.split(":");
        if (splitedGav.length == 3) {
            String dependencyGroupID = splitedGav[0];
            String dependencyArtifactID = splitedGav[1];
            String releaseVersion = splitedGav[2];
            String mavenSourceLinkBase = "https://repo1.maven.org/maven2/%s/%s/"
                    .formatted(dependencyGroupID.replaceAll("\\.", "/"), dependencyArtifactID);
            String mavenSourceLink = mavenSourceLinkBase + "%s/%s-%s-sources.jar"
                    .formatted(releaseVersion, dependencyArtifactID, releaseVersion);
            try (Response prevSourceResponse = httpConnector.newCall(new Request.Builder().url(mavenSourceLink)
                    .build()).execute()) {
                if (prevSourceResponse.code() != 404)
                    return List.of(mavenSourceLink);
            } catch (IOException e) {
                //log.error("Maven source links could not be found for the updated dependency {}.", bu.breakingCommit, e);
            }
        }
        return null;
    }

    @Override
    public AddedValueEnum getAddedValueEnum() {
        return null;
    }

    @Override
    public String getNodeId() {
        return null;
    }

    @Override
    public void setValue(String value) {

    }

    @Override
    public void computeValue() {

    }

    @Override
    public Map<String, Object> getValueMap() {
        return null;
    }

    @Override
    public Set<Map<String, String>> stringToValue(String jsonString) {
        return null;
    }

    @Override
    public String valueToString(Set<Map<String, String>> value) {
        return null;
    }

    @Override
    public Set<Map<String, String>> getValue() {
        return null;
    }

    @Override
    public Set<Map<String, String>> mergeValue(Set<Map<String, String>> computedValue, Set<Map<String, String>> computeAggregatedValue) {
        return null;
    }

    @Override
    public Set<Map<String, String>> computeMetric(String nodeId) {
        return null;
    }

    @Override
    public Set<Map<String, String>> getZeroValue() {
        return null;
    }
}
