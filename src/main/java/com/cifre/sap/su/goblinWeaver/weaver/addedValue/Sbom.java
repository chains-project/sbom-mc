package com.cifre.sap.su.goblinWeaver.weaver.addedValue;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * This class has functions to aggregate entries with SBOM information.
 */
public class Sbom extends AbstractAddedValue<Set<Map<String, String>>> {

    // Define the key terms for the SBOM formats we're interested in
    private static final List<String> SBOM_KEYWORDS = Arrays.asList("cyclonedx", "spdx");
    private static final List<String> FILE_EXTENSIONS = Arrays.asList("json", "xml");
    private static final List<String> HASH_EXTENSIONS = Arrays.asList("md5", "sha1", "sha256", "sha512");
    private final OkHttpClient httpConnector;
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public Sbom(String nodeId) {
        super(nodeId);
        httpConnector = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(120, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    /**
     * Get the Sbom links and standards from maven central if they exist.
     */
    public Set<Map<String, String>> getSbomLinks(String gav) {
        Set<Map<String, String>> sbomLinkSet = new HashSet<>();
        String[] splitedGav = gav.split(":");
        if (splitedGav.length == 3) {
            String dependencyGroupID = splitedGav[0];
            String dependencyArtifactID = splitedGav[1];
            String releaseVersion = splitedGav[2];
            // Construct base URL
            String baseUrl = constructBaseUrl(dependencyGroupID, dependencyArtifactID, releaseVersion);
            // Fetch the directory listing for the Maven artifact's version folder
            List<String> availableFiles = getAvailableFiles(baseUrl);
            // Prepare the final result map to hold sbom data
            Map<String, String> sbomLinks = new HashMap<>();
            for (String fileName : availableFiles) {
                String standard = matchesSbom(fileName);
                if (standard != null) {
                    Map<String, String> sbomData = new HashMap<>();
                    String sbomUrl = baseUrl + fileName;
                    log.info("Found SBOM: {}, Format: {}", sbomUrl, standard);
                    // Check for corresponding signature and hash files
                    boolean isSigned = availableFiles.contains(fileName + ".asc");
                    boolean isHashAvailable = containsHashFile(fileName, availableFiles);
                    // Populate the fields based on the SBOM count
                    sbomData.put("isSigned", String.valueOf(isSigned));
                    sbomData.put("isHashAvailable", String.valueOf(isHashAvailable));
                    sbomData.put("standard", standard);
                    sbomLinks.put(sbomUrl,sbomData.toString());
                }
            }
            sbomLinkSet.add(sbomLinks);
        }
        return sbomLinkSet;
    }

    /**
     * Constructs the base URL for the given groupId, artifactId, and version.
     */
    private String constructBaseUrl(String groupId, String artifactId, String version) {
        String groupPath = groupId.replace('.', '/');
        return String.format("https://repo1.maven.org/maven2/%s/%s/%s/",
                groupPath, artifactId, version);
    }

    /**
     * Retrieves the list of available files from the base URL.
     */
    private List<String> getAvailableFiles(String baseUrl) {
        List<String> fileList = new ArrayList<>();
        Request request = new Request.Builder().url(baseUrl).build();
        try (Response response = httpConnector.newCall(request).execute()) {
            if (response.isSuccessful() && response.body() != null) {
                // Assuming that the HTML page contains a directory listing (common for Maven Central)
                String htmlContent = response.body().string();
                fileList = parseHtmlForFileNames(htmlContent);
            }
        } catch (IOException e) {
            log.error("Error fetching file list from URL: {}", baseUrl, e);
        }
        return fileList;
    }

    /**
     * Parses the HTML content to extract file names.
     */
    private List<String> parseHtmlForFileNames(String htmlContent) {
        List<String> fileNames = new ArrayList<>();
        // Simple regex to extract file names from <a> tags (common in directory listings)
        String regex = "href=\"([^\"]+)\"";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
        java.util.regex.Matcher matcher = pattern.matcher(htmlContent);
        while (matcher.find()) {
            String fileName = matcher.group(1);
            if (!fileName.endsWith("/")) { // Ignore directories
                fileNames.add(fileName);
            }
        }
        return fileNames;
    }

    /**
     * Checks if the file name contains any of the SBOM keywords and ends with a supported extension.
     * Returns a list of SBOM standards ("spdx", "cyclonedx") if matched, otherwise an empty list.
     */
    private String matchesSbom(String fileName) {
        for (String keyword : SBOM_KEYWORDS) {
            for (String extension : FILE_EXTENSIONS) {
                if (fileName.toLowerCase().contains(keyword) && fileName.toLowerCase().endsWith("." + extension)) {
                    return keyword;
                }
            }
        }
        return null;
    }

    /**
     * Checks if any hash file exists for the given SBOM file.
     */
    private boolean containsHashFile(String fileName, List<String> availableFiles) {
        for (String hashExt : HASH_EXTENSIONS) {
            if (availableFiles.contains(fileName + "." + hashExt)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public AddedValueEnum getAddedValueEnum() {
        return AddedValueEnum.SBOM;
    }

    @Override
    public void computeValue() {
        value = getSbomLinks(nodeId);
    }

    @Override
    public Set<Map<String, String>> stringToValue(String jsonString) {
        Set<Map<String, String>> resultSet = new HashSet<>();
        try {
            JSONParser parser = new JSONParser();
            JSONObject jsonObject = (JSONObject) parser.parse(jsonString);
            JSONArray sbomArray = (JSONArray) jsonObject.get(getAddedValueEnum().getJsonKey());

            if (sbomArray != null) {
                for (Object obj : sbomArray) {
                    JSONObject sbomJson = (JSONObject) obj;
                    Map<String, String> sbomMap = new HashMap<>();
                    // Dynamically map all key-value pairs in the JSON object
                    for (Object keyObj : sbomJson.keySet()) {
                        String key = (String) keyObj;
                        String value = sbomJson.get(key) != null ? sbomJson.get(key).toString() : "";
                        sbomMap.put(key, value);
                    }
                    resultSet.add(sbomMap);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return resultSet;
    }

    @Override
    public String valueToString(Set<Map<String, String>> value){
        JSONArray jsonArray = new JSONArray();
        for (Map<String, String> map : value) {
            JSONObject jsonObject = new JSONObject();
            jsonObject.putAll(map);
            jsonArray.add(jsonObject);
        }
        JSONObject finalObject = new JSONObject();
        finalObject.put(getAddedValueEnum().getJsonKey(), jsonArray);
        return finalObject.toJSONString().replace("\"", "\\\"");
    }
}
