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
 * This class has functions to aggregate entries with sbom information.
 */
public class Sbom extends AbstractAddedValue<Set<Map<String, String>>> {

    // Define the key terms for the SBOM formats we're interested in
    private static final List<String> SBOM_KEYWORDS = Arrays.asList("cyclonedx", "spdx");
    private static final List<String> FILE_EXTENSIONS = Arrays.asList("json", "xml");
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
     * Get the Maven source jar links for the old and new dependency releases if they exist.
     */
    public Set<Map<String, String>> getMavenSourceLinks(String gav) {
        Set<Map<String, String>> sbomLinks = new HashSet<>();
        String[] splitedGav = gav.split(":");
        if (splitedGav.length == 3) {
            String dependencyGroupID = splitedGav[0];
            String dependencyArtifactID = splitedGav[1];
            String releaseVersion = splitedGav[2];

            // Construct base URL
            String baseUrl = constructBaseUrl(dependencyGroupID, dependencyArtifactID, releaseVersion);

            // Fetch the directory listing for the Maven artifact's version folder
            List<String> availableFiles = getAvailableFiles(baseUrl);

            // Prepare lists to collect all SBOM formats and links
            Set<String> standardsSet = new HashSet<>();
            List<String> linksList = new ArrayList<>();

            // Check if any of the available files match our SBOM criteria
            for (String fileName : availableFiles) {
                String standards = matchesSbom(fileName);
                if (standards != null) {
                    String sbomUrl = baseUrl + fileName;
                    linksList.add(sbomUrl);
                    standardsSet.add(standards);
                    log.info("Found SBOM: {}, Format: {}", sbomUrl, String.join(",", standards));
                }
            }

            // Prepare the final result
            Map<String, String> sbomData = new HashMap<>();
            if (!standardsSet.isEmpty()) {
                sbomData.put("isExist", "true");
                sbomData.put("standard", String.join(",", standardsSet));
                sbomData.put("link", String.join(",", linksList));
            } else {
                // No SBOMs were found
                sbomData.put("isExist", "false");
                sbomData.put("standard", "");
                sbomData.put("link", "");
            }
            sbomLinks.add(sbomData);
        }
        return sbomLinks;
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


    @Override
    public AddedValueEnum getAddedValueEnum() {
        return AddedValueEnum.SBOM;
    }

    @Override
    public void computeValue() {
        value = getMavenSourceLinks(nodeId);
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

                    Map<String, String> sbomMap = Map.of(
                            "isExist", (String) sbomJson.get("isExist"),
                            "standard", (String) sbomJson.get("standard"),
                            "link", (String) sbomJson.get("link")
                    );
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
