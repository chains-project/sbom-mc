import os
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any
from collections import Counter

class SBOMParser:
    def __init__(self, base_dir: str = 'sbom'):
        self.base_dir = base_dir
        self.results = {"sboms": []}

    def process_all_files(self) -> Dict[str, List[Dict[str, Any]]]:
        try:
            for root, _, files in os.walk(self.base_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if 'cyclonedx' in file.lower():
                            if file.endswith('.json'):
                                self._process_cyclonedx_json(file_path)
                            elif file.endswith('.xml'):
                                self._process_cyclonedx_xml(file_path)
                    except Exception as e:
                        print(f"Error processing {file_path}: {str(e)}")
                        continue
        except Exception as e:
            print(f"Error walking directory {self.base_dir}: {str(e)}")

        return self.results

    def _process_cyclonedx_json(self, file_path: str) -> None:
        print(f"Processing CycloneDX JSON file: {file_path}")
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            metadata_group = data.get('metadata', {}).get('component', {}).get('group', '')
            metadata_name = data.get('metadata', {}).get('component', {}).get('name', '')
            metadata_version = data.get('metadata', {}).get('component', {}).get('version', '')
            dependencies = []
            if 'dependencies' in data:
                refs_in_depends_on = set()
                for dep in data['dependencies']:
                    refs_in_depends_on.update(dep.get('dependsOn', []))
                metadata_match = None
                for dep in data['dependencies']:
                    ref = dep.get('ref', '')
                    if (metadata_group and metadata_group in ref and
                        metadata_name and metadata_name in ref and
                        metadata_version and metadata_version in ref):
                        metadata_match = dep
                        break
                for dep in data['dependencies']:
                    ref = dep.get('ref', '')
                    if metadata_match and dep == metadata_match:
                        dependencies.extend(dep.get('dependsOn', []))
                        break

                    # Default processing
                    # Keep ref only if it does not appear in any dependsOn
                    # and does not appear multiple times
                    if ref and ref not in refs_in_depends_on:
                        dependencies.append(ref)
                dependencies = list(dict.fromkeys(dependencies))

            self.results['sboms'].append({
                "file_path": file_path,
                "type": "cyclonedx-json",
                "dependencies": dependencies,
                "dependency_count": len(dependencies)
            })
        except json.JSONDecodeError as e:
            print(f"JSON parsing error in {file_path}: {str(e)}")
        except Exception as e:
            print(f"Unexpected error processing {file_path}: {str(e)}")

    def _process_cyclonedx_xml(self, file_path: str) -> None:
        """Process CycloneDX XML file with advanced dependency filtering."""
        print(f"Processing CycloneDX XML file: {file_path}")
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            ns = {'ns': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
            metadata_ref = ''
            metadata_group = ''
            metadata_name = ''
            metadata_version = ''
            metadata_elem = root.find('.//ns:metadata/ns:component' if ns else './/metadata/component', ns)
            if metadata_elem is not None:
                metadata_ref = metadata_elem.get('bom-ref', '')
                group_elem = metadata_elem.find('ns:group' if ns else 'group', ns)
                name_elem = metadata_elem.find('ns:name' if ns else 'name', ns)
                version_elem = metadata_elem.find('ns:version' if ns else 'version', ns)
                metadata_group = group_elem.text if group_elem is not None else ''
                metadata_name = name_elem.text if name_elem is not None else ''
                metadata_version = version_elem.text if version_elem is not None else ''

            special_dependency = None
            dependencies = []
            dependency_elements = root.findall('.//ns:dependency' if ns else './/dependency', ns)

            for dep in dependency_elements:
                ref = dep.get('ref', '')
                if (metadata_group and metadata_group in ref and
                    metadata_name and metadata_name in ref and
                    metadata_version and metadata_version in ref):
                    special_dependency = dep
                    break
            if special_dependency is not None:
                nested_deps = special_dependency.findall('.//ns:dependency' if ns else './/dependency', ns)
                dependencies = [d.get('ref', '') for d in nested_deps if d.get('ref', '')]
            if not dependencies:
                all_deps = []
                for dep in dependency_elements:
                    ref = dep.get('ref', '')
                    if ref:
                        all_deps.append(ref)
                deps_counter = Counter(all_deps)
                dependencies = [
                    ref for ref, count in deps_counter.items()
                    if count == 1 and not (
                        metadata_group and metadata_group in ref and
                        metadata_name and metadata_name in ref and
                        metadata_version and metadata_version in ref
                    )
                ]
            self.results['sboms'].append({
                "file_path": file_path,
                "type": "cyclonedx-xml",
                "dependencies": dependencies,
                "dependency_count": len(dependencies)
            })
        except ET.ParseError as e:
            print(f"XML parsing error in {file_path}: {str(e)}")
        except Exception as e:
            print(f"Unexpected error processing {file_path}: {str(e)}")

def main():
    parser = SBOMParser()
    results = parser.process_all_files()
    output_file = 'sbom_dependencies.json'
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {output_file}")
    except Exception as e:
        print(f"Error saving results: {str(e)}")
        print("\nResults:")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()