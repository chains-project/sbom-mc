# Software Bills of Materials in Maven Central

This repository is an extension of the [Goblin Weaver](https://github.com/Goblin-Ecosystem/goblinWeaver) that allows augmenting the Maven Central dependency graph with Software Bills of Materials (SBOMs) published in Maven Central.

The derived SBOM dataset can be downloaded from [Zenodo](https://zenodo.org/records/10047561). 
This dataset includes:  

1. The collected SBOMs from Maven Central.  
2. A Neo4J dump of Maven Central dependency graph augmented with SBOM URLs.  

More details can be found in this paper: Software Bills of Materials in Maven Central (link to be added).

## Added values
In addition to the [added values supported by the original Goblin weaver](https://github.com/Goblin-Ecosystem/goblinWeaver?tab=readme-ov-file#added-values), this work supports adding SBOM data to release nodes.
- SBOM: Corresponds to the existence of an SBOM in Maven Central.

## Requirements
- Java 17
- Maven, with MAVEN_HOME defines
- An active Neo4j database containing the Maven Central dependency graph.

## Build
To build this project, run:
> mvn clean package

## Run
To launch the API, you must provide the URI, user and password of your Neo4J database containing the Maven Central dependency graph.  
The program will first download the osv.dev dataset and create a folder called "osvData", it's takes approximately 3m30s.  
If you already have downloaded this dataset and you don't want to update it, you can add the "noUpdate" argument on the java -jar command.

Example:
> java -Dneo4jUri="bolt://localhost:7687/" -Dneo4jUser="neo4j" -Dneo4jPassword="Password1" -jar goblinWeaver-2.1.0.jar


> java -Dneo4jUri="bolt://localhost:7687/" -Dneo4jUser="neo4j" -Dneo4jPassword="Password1" -jar goblinWeaver-2.1.0.jar noUpdate

## Use the API
Pre-designed requests are available, but you can also send your own Cypher requests directly to the API.  
You can add to the body query for the API a list of Added values, and it will enrich the result for you.

A swagger documentation of the API is available here:
> http://localhost:8080/swagger-ui/index.html

## Licensing
Copyright 2024 SAP SE or an SAP affiliate company and Neo4j Ecosystem Weaver. Please see our [LICENSE](LICENSE) for copyright and license information.
