# Data Overview

This folder contains data collected from experiments using SBOMs (Software Bill of Materials) derived from Maven Central dependency graph. 

---

## Contents

### 1. **SBOM Tools**  
- **File:** `sbom_tools.csv`  
  Contains details of the SBOM generation tools used, as documented in each SBOM.

---

### 2. **Dependency Data**  

#### a. **Graph Dependencies**  
- **File:** `graph_dependencies.ndjson`  
  Lists the dependencies collected from Maven Central dependency graph.

#### b. **SBOM Dependencies**  
- **File:** `sbom_dependencies.json`  
  Lists the dependencies collected from CycloneDX SBOMs.

#### c. **Dependency Counts**  
- **File:** `dependency_counts.csv`  

  - **`sbom_deps`:** The number of dependencies recorded in the SBOM.  
  - **`graph_deps`:** Dependency count (excluding test dependencies) derived from Maven Central dependency graph.  
  - **`dependencies_match`:** Indicates whether the dependencies from the graph and the SBOM align.  

> **Note:** All counts were programmatically collected and not manually verified. SBOMs that include parent POM files as dependencies may show inconsistencies due to the inability to infer direct dependencies using SBOMs alone.

#### d. **Dependency Mismatches**  
- **File:** `dependency_mismatches.json`  
  Details mismatches between dependencies collected from SBOMs and those derived from the graph, including:  
    - Cases where the dependency counts differ.  
    - Cases where the dependency counts are identical, but the actual dependencies differ.  

- **File:** `subtle_dependency_mismatches.csv`  
  A filtered subset of releases where:  
  - Dependency counts are identical between Maven Central dependency graph and the SBOM. However, specific dependencies (defined by `groupId`, `artifactId`, and `version`) differ between the two sources.

---

### 3. **Scripts**  
The scripts folder contains the scripts used to extract the data mentioned above.
