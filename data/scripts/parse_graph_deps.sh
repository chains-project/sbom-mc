#!/bin/bash

curl -X POST \
  http://localhost:7474/db/data/transaction/commit \
  -H "Authorization: Basic $(echo -n 'neo4j:Password1' | base64)" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{
    "statements": [{
      "statement": "MATCH (sbomRelease:Release)-[:addedValues]->(v:AddedValue) WHERE v.type = '\''SBOM'\'' AND v.value CONTAINS '\''https'\'' WITH sbomRelease OPTIONAL MATCH (sbomRelease)-[e:dependency]->(a) WHERE e.scope <> '\''test'\'' RETURN sbomRelease.id AS releaseId, COUNT(a) AS dependencyCount, COLLECT(a.id + '\'':'\'' + e.targetVersion) AS dependenciesWithVersions",
      "resultDataContents": ["row"]
    }]
  }' | \
  jq -c '.results[0].data[] | {releaseId: .row[0], dependencyCount: .row[1], dependenciesWithVersions: .row[2]}' > graph_dependencies.json
