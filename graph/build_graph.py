
import csv
import json
import re
from pathlib import Path
from collections import Counter, defaultdict

import networkx as nx


ROOT = Path(__file__).resolve().parents[1]

CHALLENGES_FILE = ROOT / "findings" / "challenges.csv"
MAPPING_FILE = ROOT / "mapping" / "cwe_capec_attack.json"
INVENTORY_FILE = ROOT / "recon" / "service_inventory.csv"
OPENAPI_FILE = ROOT / "recon" / "openapi_spec.json"

OUTPUT_DIR = ROOT / "graph"

GRAPHML_FILE = OUTPUT_DIR / "attack_graph.graphml"
JSON_FILE = OUTPUT_DIR / "attack_graph.json"
NODES_FILE = OUTPUT_DIR / "graph_nodes.csv"
EDGES_FILE = OUTPUT_DIR / "graph_edges.csv"
SUMMARY_FILE = OUTPUT_DIR / "graph_summary.json"


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        return list(csv.DictReader(file))


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def clean(value):
    return str(value or "").strip()


def resolve_evidence_folder(challenge_no, raw_path):
    """
    Önce CSV'deki yolu kontrol eder.
    Bulamazsa klasör adındaki Challenge numarasına göre arar.
    """

    raw_path = clean(raw_path)

    # Önce CSV'deki mevcut yolu dene.
    if raw_path:
        candidate = ROOT / raw_path
        if candidate.is_dir():
            return candidate.relative_to(ROOT).as_posix()

    evidence_root = ROOT / "findings" / "evidence"

    if not evidence_root.is_dir():
        return None

    try:
        challenge_token = f"{int(challenge_no):02d}"
    except (TypeError, ValueError):
        return None

    matches = [
        folder
        for folder in evidence_root.iterdir()
        if folder.is_dir()
        and challenge_token in folder.name.split("_")
    ]

    # Yalnızca tek ve kesin eşleşme varsa döndür.
    if len(matches) == 1:
        return matches[0].relative_to(ROOT).as_posix()

    return None



def normalize(value):
    return re.sub(r"[^a-z0-9]", "", clean(value).lower())


def add_node(graph, node_id, node_type, label, **attributes):
    data = {
        "node_type": str(node_type),
        "label": str(label)
    }

    for key, value in attributes.items():
        if value is not None:
            data[key] = str(value)

    if graph.has_node(node_id):
        graph.nodes[node_id].update(data)
    else:
        graph.add_node(node_id, **data)


def add_edge(graph, source_node, target_node, relation, **attributes):
    data = {"relation": relation}

    for key, value in attributes.items():
        if value is not None:
            data[key] = str(value)

    graph.add_edge(source_node, target_node, **data)


def split_ids(value, prefix):
    if not value:
        return []

    pattern = rf"{prefix}-\d+"
    return list(dict.fromkeys(re.findall(pattern, str(value).upper())))


def candidate_items(value):
    if isinstance(value, list):
        return value

    if isinstance(value, dict):
        return [value]

    return []


def build_service_index(inventory):
    service_nodes = {}
    aliases = {}

    for row in inventory:
        service_id = clean(row.get("service_id"))

        if not service_id:
            continue

        node_id = f"service:{service_id}"
        service_nodes[service_id] = node_id

        for field in ("service_id", "service_name"):
            value = clean(row.get(field))
            if value:
                aliases[normalize(value)] = node_id

    return service_nodes, aliases


def find_service_for_path(path, inventory, aliases, base_variable=None):
    # API yüzeyindeki açıkça tanımlanmış path öneklerini kullan.
    matches = []

    for row in inventory:
        surface = clean(row.get("api_surface"))

        for entry in surface.split(";"):
            entry = entry.strip()

            if not entry.startswith("/"):
                continue

            prefix = entry.split("*")[0]

            if prefix and path.startswith(prefix):
                matches.append((len(prefix), row))

    if matches:
        matches.sort(key=lambda item: item[0], reverse=True)
        return matches[0][1], "inventory_api_surface"

    # Postman koleksiyonundaki url_mail değişkenini
    # envanterdeki mailhog kaydıyla ilişkilendir.
    if base_variable == "url_mail":
        for row in inventory:
            name = normalize(row.get("service_name"))
            service_id = normalize(row.get("service_id"))

            if "mailhog" in name or "mailhog" in service_id:
                return row, "postman_url_mail_variable"

    return None, None


def add_mapping_node(graph, finding_id, kind, item, relation):
    mapping_id = clean(
        item.get("id") or item.get("normalized_id")
    )

    if not mapping_id:
        return

    if kind == "cwe":
        node_type = "weakness"
    elif kind == "capec":
        node_type = "attack_pattern"
    else:
        node_type = "attack_technique"

    title = clean(item.get("title")) or mapping_id
    node_id = f"{kind.upper()}:{mapping_id}"

    add_node(
        graph,
        node_id,
        node_type,
        f"{mapping_id}: {title}",
        mapping_id=mapping_id,
        title=title,
        confidence=item.get("confidence", ""),
        verification_status=item.get(
            "mapping_verification_status",
            "not_verified"
        ),
        source_url=item.get("source_url", ""),
        human_review_required=item.get(
            "human_review_required",
            True
        ),
        rationale=item.get("rationale", ""),
        deprecated=item.get("deprecated", False)
    )

    add_edge(
        graph,
        finding_id,
        node_id,
        relation,
        confidence=item.get("confidence", ""),
        verification_status=item.get(
            "mapping_verification_status",
            "not_verified"
        ),
        rationale=item.get("rationale", "")
    )


def add_recorded_mapping(graph, finding_id, kind, mapping_id, mapping_info=None):
    if not mapping_id:
        return

    mapping_info = mapping_info or {}

    node_type = {
        "cwe": "weakness",
        "capec": "attack_pattern",
        "attack": "attack_technique"
    }[kind]

    node_id = f"{kind.upper()}:{mapping_id}"

    title = clean(mapping_info.get("title")) or mapping_id

    add_node(
        graph,
        node_id,
        node_type,
        f"{mapping_id}: {title}",
        mapping_id=mapping_id,
        title=title,
        verification_status=(
            "verified"
            if mapping_info.get("verified") is True
            else "recorded_but_not_verified"
        ),
        source_url=mapping_info.get("source_url", ""),
        assessment=mapping_info.get("assessment", "")
    )

    add_edge(
        graph,
        finding_id,
        node_id,
        f"recorded_{kind}_mapping",
        verification_status=(
            "verified"
            if mapping_info.get("verified") is True
            else "recorded_but_not_verified"
        )
    )


def main():
    for path in (
        CHALLENGES_FILE,
        MAPPING_FILE,
        INVENTORY_FILE,
        OPENAPI_FILE
    ):
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    challenges = read_csv(CHALLENGES_FILE)
    inventory = read_csv(INVENTORY_FILE)
    mapping_data = read_json(MAPPING_FILE)
    openapi = read_json(OPENAPI_FILE)

    mapping_index = {
        str(item.get("challenge_no")): item
        for item in mapping_data.get("findings", [])
    }

    graph = nx.MultiDiGraph()

    # -------------------------------------------------
    # 1. Root system node
    # -------------------------------------------------

    system_id = "system:crAPI"

    add_node(
        graph,
        system_id,
        "system",
        "crAPI System",
        target="crAPI"
    )

    # -------------------------------------------------
    # 2. Service inventory
    # -------------------------------------------------

    service_nodes, service_aliases = build_service_index(inventory)

    for row in inventory:
        service_id = clean(row.get("service_id"))

        if not service_id:
            continue

        node_id = service_nodes[service_id]

        service_name = clean(
            row.get("service_name") or service_id
        )

        add_node(
            graph,
            node_id,
            "service",
            service_name,
            service_id=service_id,
            service_type=row.get("service_type", ""),
            technology=row.get("technology", ""),
            language=row.get("language", ""),
            port=row.get("port", ""),
            exposure=row.get("exposure", ""),
            api_surface=row.get("api_surface", ""),
            source_status=row.get("source_status", "")
        )

        add_edge(
            graph,
            system_id,
            node_id,
            "contains"
        )

    # -------------------------------------------------
    # 3. Explicit service dependencies
    # -------------------------------------------------

    for row in inventory:
        source_id = clean(row.get("service_id"))

        if source_id not in service_nodes:
            continue

        source_node = service_nodes[source_id]

        dependencies = clean(row.get("depends_on"))

        for dependency in dependencies.split(";"):
            dependency = dependency.strip()

            if not dependency:
                continue

            target_node = service_aliases.get(
                normalize(dependency)
            )

            if target_node:
                add_edge(
                    graph,
                    source_node,
                    target_node,
                    "depends_on",
                    source="service_inventory.csv"
                )

    # -------------------------------------------------
    # 4. OpenAPI endpoint nodes
    # -------------------------------------------------

    openapi_paths = openapi.get("paths", {})
    endpoint_nodes_by_path = defaultdict(list)

    for path, methods in openapi_paths.items():
        for method, operation in methods.items():
            method = method.upper()

            if method not in (
                "GET", "POST", "PUT", "PATCH",
                "DELETE", "OPTIONS", "HEAD", "TRACE"
            ):
                continue

            endpoint_id = f"endpoint:{method}:{path}"
            
            add_node(
                graph,
                endpoint_id,
                "endpoint",
                f"{method} {path}",
                path=path,
                method=method,
                openapi_match=True,
                operation_id=operation.get("operationId", ""),
                summary=operation.get("summary", ""),
                postman_request_count=operation.get(
                    "x-postman-request-count", 1
                ),
                base_variable=operation.get(
                    "x-postman-base-variable", ""
                )
            )

            endpoint_nodes_by_path[path].append(endpoint_id)

            service, match_basis = find_service_for_path(
                path,
                inventory,
                service_aliases,
                operation.get("x-postman-base-variable")
            )

            if service:
                service_id = clean(service.get("service_id"))
                service_node = service_nodes.get(service_id)

                if service_node:
                    add_edge(
                        graph,
                        service_node,
                        endpoint_id,
                        "exposes",
                        match_basis=match_basis
                    )

   
    # -------------------------------------------------
    # 5. Challenge / finding nodes
    # -------------------------------------------------

    matched_findings = 0
    unmatched_endpoints = []
    missing_evidence = []

    for row in challenges:
        number = clean(row.get("challenge_no"))
        category = clean(row.get("kategori")) or "Unknown"
        status = clean(row.get("durum")) or "unspecified"
        endpoint = clean(row.get("endpoint"))

        finding_id = f"finding:challenge:{number}"

        mapping_item = mapping_index.get(number, {})

        # Gerçek kanıt klasörünü bul
        evidence_folder = resolve_evidence_folder(
            number,
            row.get("kanit_klasoru", "")
        )

        # Finding node oluştur
        add_node(
            graph,
            finding_id,
            "finding",
            f"Challenge {number}: {category}",
            challenge_no=number,
            category=category,
            finding_status=status,
            source=row.get("kaynak", ""),
            endpoint=endpoint,
            evidence_folder=evidence_folder or "",
            evidence_folder_source=clean(
                row.get("kanit_klasoru", "")
            ),
            cwe=row.get("cwe", ""),
            capec=row.get("capec", ""),
            attack=row.get("attack", ""),
            notes=row.get("notlar", ""),
            finding_validation_state=mapping_item.get(
                "finding_validation_state",
                "not_available"
            )
        )

        # Evidence path existence check
        if evidence_folder:
            evidence_path = ROOT / evidence_folder

            if not evidence_path.is_dir():
                missing_evidence.append({
                    "challenge_no": number,
                    "path": evidence_folder
                })
        else:
            missing_evidence.append({
                "challenge_no": number,
                "path": clean(row.get("kanit_klasoru", "")),
                "reason": "No unique matching evidence folder found."
            })

        # -------------------------------------------------
        # Find endpoint in OpenAPI
        # -------------------------------------------------

        matching_endpoints = endpoint_nodes_by_path.get(
            endpoint, []
        )

        if matching_endpoints:
            matched_findings += 1

            for endpoint_id in matching_endpoints:
                add_edge(
                    graph,
                    endpoint_id,
                    finding_id,
                    "has_finding",
                    source="challenges.csv"
                )

        else:
            unmatched_endpoints.append({
                "challenge_no": number,
                "endpoint": endpoint
            })

            endpoint_id = f"endpoint:unlisted:{endpoint}"

            add_node(
                graph,
                endpoint_id,
                "endpoint",
                f"Unlisted API: {endpoint}",
                path=endpoint,
                method="UNKNOWN",
                openapi_match=False
            )

            service, match_basis = find_service_for_path(
                endpoint,
                inventory,
                service_aliases
            )

            if service:
                service_id = clean(service.get("service_id"))
                service_node = service_nodes.get(service_id)

                if service_node:
                    add_edge(
                        graph,
                        service_node,
                        endpoint_id,
                        "exposes",
                        match_basis=match_basis
                    )

            add_edge(
                graph,
                endpoint_id,
                finding_id,
                "has_finding",
                source="challenges.csv"
            )

        # -------------------------------------------------
        # 6. Recorded mappings from CSV and mapping JSON
        # -------------------------------------------------

        existing = mapping_item.get("existing_mappings", {})

        for kind, csv_field, prefix in (
            ("cwe", "cwe", "CWE"),
            ("capec", "capec", "CAPEC"),
            ("attack", "attack", "T")
        ):
            info = existing.get(kind, {})

            if isinstance(info, dict):
                recorded_id = clean(info.get("id"))
            else:
                recorded_id = ""

            if recorded_id:
                add_recorded_mapping(
                    graph,
                    finding_id,
                    kind,
                    recorded_id,
                    info
                )

            csv_value = clean(row.get(csv_field))

            if kind == "attack":
                csv_ids = re.findall(
                    r"T\d{4}(?:\.\d{3})?",
                    csv_value.upper()
                )
            else:
                csv_ids = split_ids(csv_value, prefix)

            for mapping_id in csv_ids:
                add_recorded_mapping(
                    graph,
                    finding_id,
                    kind,
                    mapping_id,
                    info if recorded_id == mapping_id else {}
                )

        # -------------------------------------------------
        # 7. Candidate mappings
        # -------------------------------------------------

        candidates = mapping_item.get("candidates", {})

        for kind in ("cwe", "capec", "attack"):
            for candidate in candidate_items(
                candidates.get(kind, [])
            ):
                add_mapping_node(
                    graph,
                    finding_id,
                    kind,
                    candidate,
                    f"candidate_{kind}_mapping"
                )

    # -------------------------------------------------
    # 8. Export graph files
    # -------------------------------------------------

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    nx.write_graphml(
        graph,
        GRAPHML_FILE,
        encoding="utf-8"
    )

    JSON_FILE.write_text(
        json.dumps(
            nx.node_link_data(graph),
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    # Nodes CSV
    node_rows = []

    for node_id, attributes in graph.nodes(data=True):
        node_rows.append({
            "id": node_id,
            **attributes
        })

    node_fields = sorted({
        key
        for row in node_rows
        for key in row.keys()
    })

    with NODES_FILE.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=node_fields
        )
        writer.writeheader()
        writer.writerows(node_rows)

    # Edges CSV
    edge_rows = []

    for source, target, key, attributes in graph.edges(
        keys=True,
        data=True
    ):
        edge_rows.append({
            "source": source,
            "target": target,
            "key": key,
            **attributes
        })

    edge_fields = sorted({
        field
        for row in edge_rows
        for field in row.keys()
    })

    with EDGES_FILE.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=edge_fields
        )
        writer.writeheader()
        writer.writerows(edge_rows)

    # -------------------------------------------------
    # 9. Summary and warnings
    # -------------------------------------------------

    node_types = Counter(
        data.get("node_type", "unknown")
        for _, data in graph.nodes(data=True)
    )

    edge_types = Counter(
        data.get("relation", "unknown")
        for _, _, data in graph.edges(data=True)
    )

    finding_statuses = Counter(
        clean(row.get("durum")) or "unspecified"
        for row in challenges
    )

    attack_nodes = node_types.get("attack_technique", 0)

    warnings = []

    if unmatched_endpoints:
        warnings.append(
            f"{len(unmatched_endpoints)} challenge endpoint "
            "was not found in the Postman-derived OpenAPI paths."
        )

    if missing_evidence:
        warnings.append(
            f"{len(missing_evidence)} evidence folder paths "
            "were not found on disk."
        )

    if attack_nodes == 0:
        warnings.append(
            "No ATT&CK technique IDs were found in the supplied "
            "CSV or mapping candidates. No ATT&CK nodes were invented."
        )

    summary = {
        "graph_type": "directed_multigraph",
        "target": "crAPI",
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "challenge_count": len(challenges),
        "service_count": node_types.get("service", 0),
        "endpoint_count": node_types.get("endpoint", 0),
        "finding_count": node_types.get("finding", 0),
        "weakness_count": node_types.get("weakness", 0),
        "attack_pattern_count": node_types.get("attack_pattern", 0),
        "attack_technique_count": attack_nodes,
        "openapi_matched_findings": matched_findings,
        "unmatched_challenge_endpoints": unmatched_endpoints,
        "missing_evidence_folders": missing_evidence,
        "finding_status_distribution": dict(finding_statuses),
        "node_type_distribution": dict(node_types),
        "edge_type_distribution": dict(edge_types),
        "warnings": warnings,
        "mapping_note": (
            "Recorded mappings and candidate mappings are kept "
            "separate. Candidate mappings are not treated as verified."
        )
    }

    SUMMARY_FILE.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    # -------------------------------------------------
    # 10. Console report
    # -------------------------------------------------

    print("\n========== ATTACK GRAPH CREATED ==========")
    print("Graph nodes:", graph.number_of_nodes())
    print("Graph edges:", graph.number_of_edges())
    print("Services:", node_types.get("service", 0))
    print("Endpoints:", node_types.get("endpoint", 0))
    print("Findings:", node_types.get("finding", 0))
    print("CWE nodes:", node_types.get("weakness", 0))
    print("CAPEC nodes:", node_types.get("attack_pattern", 0))
    print("ATT&CK nodes:", attack_nodes)

    print("\nOpenAPI matched findings:", matched_findings)
    print("Unmatched challenge endpoints:", len(unmatched_endpoints))
    print("Missing evidence folders:", len(missing_evidence))

    print("\nGenerated files:")
    for path in (
        GRAPHML_FILE,
        JSON_FILE,
        NODES_FILE,
        EDGES_FILE,
        SUMMARY_FILE
    ):
        print("-", path.relative_to(ROOT))

    if warnings:
        print("\nWARNINGS:")
        for warning in warnings:
            print("-", warning)
    else:
        print("\nNo warnings.")

    print("\nAttack graph generation completed.")


if __name__ == "__main__":
    main()
