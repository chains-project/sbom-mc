import json
import csv
import os

with open('sbom_dependencies.json', 'r') as f1:
    sbom_data = json.load(f1)

with open('graph_dependencies.json', 'r') as f2:
    release_data = [json.loads(line) for line in f2]

def parse_maven_pkg(pkg_str):
    pkg_str = pkg_str.replace('pkg:maven/', '').split('?')[0]
    parts = pkg_str.split('@')
    coords = parts[0].split('/')
    group_id = coords[0]
    artifact_id = coords[1]
    version = parts[1] if len(parts) > 1 else ''
    return (group_id, artifact_id, version)

def parse_release_id_dependency(dep_str):
    parts = dep_str.split(':')
    if len(parts) == 3:
        return (parts[0], parts[1], parts[2])
    return None

release_map = {
    item["releaseId"]: {
        "dependencyCount": item["dependencyCount"],
        "dependencies": [
            parse_release_id_dependency(dep) for dep in item.get("dependenciesWithVersions", [])
        ]
    } for item in release_data
}

def transform_file_path(file_path):
    core_path = file_path[len("sbom/"):file_path.rfind("/")]
    segments = core_path.split("/")
    group_id = ".".join(segments[0:-2])
    artifact_id = segments[-2]
    version = segments[-1]
    return f"{group_id}:{artifact_id}:{version}"

output_rows = [
    ["file_path", "releaseId", "sbom_deps", "graph_deps", "dependencies_match"]
]
unmapped_sboms = []
detailed_comparison_results = []
simplified_comparison_results = []
for sbom in sbom_data["sboms"]:
    file_path = sbom["file_path"]
    sbom_deps = sbom["dependency_count"]
    transformed_id = transform_file_path(file_path)
    if transformed_id in release_map:
        release_info = release_map[transformed_id]
        graph_deps = release_info["dependencyCount"]
        sbom_dependencies = [
            parse_maven_pkg(dep) for dep in sbom.get("dependencies", [])
        ]
        dependencies_match = False
        if sbom_deps == graph_deps:
            sbom_deps_set = set(sbom_dependencies)
            graph_deps_set = set(release_info["dependencies"])
            dependencies_match = sbom_deps_set == graph_deps_set
        output_rows.append([
            file_path,
            transformed_id,
            sbom_deps,
            graph_deps,
            dependencies_match
        ])
        if not dependencies_match:
            detailed_comparison_results.append({
                "file_path": file_path,
                "releaseId": transformed_id,
                "sbom_deps": sbom_deps,
                "graph_deps": graph_deps,
                "sbom_dependencies": sbom_dependencies,
                "graph_dependencies": release_info["dependencies"]
            })
            simplified_comparison_results.append({
                "releaseId": transformed_id,
                "sbom_deps": sbom_dependencies,
                "graph_deps": release_info["dependencies"]
            })
    else:
        unmapped_sboms.append(transformed_id)

with open('dependency_counts.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(output_rows)

with open('dependency_count_mismatches.json', 'w') as f:
    json.dump(detailed_comparison_results, f, indent=2)

# with open('simplified_dependency_mismatches.json', 'w') as f:
#     json.dump(simplified_comparison_results, f, indent=2)

print(len(detailed_comparison_results))
