import csv

def filter_dependency_mismatches(input_csv, output_csv):
    with open(input_csv, 'r', newline='') as infile:
        reader = csv.DictReader(infile)
        output_rows = []
        for row in reader:
            sbom_deps = int(row['sbom_deps'])
            graph_deps = int(row['graph_deps'])
            dependencies_match = row['dependencies_match'].lower() == 'false'
            if sbom_deps == graph_deps and dependencies_match:
                output_rows.append(row)
    with open(output_csv, 'w', newline='') as outfile:
        if output_rows:
            fieldnames = reader.fieldnames
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(output_rows)

    print(f"Found {len(output_rows)} rows where dependency counts match but dependencies differ.")
    return output_rows

input_csv = 'dependency_counts.csv'
output_csv = 'subtle_dependency_mismatches.csv'
mismatched_rows = filter_dependency_mismatches(input_csv, output_csv)
