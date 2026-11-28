
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "recon" / "postman_collection.json"
OUTPUT = ROOT / "recon" / "openapi_spec.json"


def get_description(value):
    if isinstance(value, dict):
        return value.get("content", "")
    return str(value).strip() if value else ""


def infer_schema(value):
    if isinstance(value, dict):
        return {
            "type": "object",
            "properties": {
                str(key): infer_schema(item)
                for key, item in value.items()
            },
            "additionalProperties": True
        }

    if isinstance(value, list):
        schema = {"type": "array"}
        if value:
            schema["items"] = infer_schema(value[0])
        else:
            schema["items"] = {}
        return schema

    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if value is None:
        return {"nullable": True}

    return {"type": "string"}


def get_url_parts(url):
    if isinstance(url, dict):
        raw = url.get("raw", "")

        if not raw:
            host = url.get("host", [])
            if isinstance(host, list):
                host = ".".join(host)

            path_parts = url.get("path", [])
            if isinstance(path_parts, list):
                path = "/".join(path_parts)
            else:
                path = str(path_parts)

            protocol = url.get("protocol", "")
            prefix = f"{protocol}://" if protocol else ""
            raw = f"{prefix}{host}/{path}"

        query_entries = url.get("query", [])
    else:
        raw = str(url)
        query_entries = []

    base_match = re.match(r"^\{\{([^}]+)\}\}", raw)
    base_variable = None

    if base_match:
        base_variable = base_match.group(1)
        raw = raw[base_match.end():]

    parsed = urlsplit(raw)

    path = parsed.path or "/"
    path = re.sub(r"\{\{([^}]+)\}\}", r"{\1}", path)

    query_params = []

    for entry in query_entries:
        if entry.get("disabled", False):
            continue

        key = entry.get("key")
        if key:
            query_params.append({
                "name": key,
                "in": "query",
                "required": False,
                "schema": {"type": "string"}
            })

    if not query_params:
        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        ):
            query_params.append({
                "name": key,
                "in": "query",
                "required": False,
                "schema": {"type": "string"}
            })

    return path, query_params, base_variable


def get_request_body(request):
    body = request.get("body")

    if not isinstance(body, dict):
        return None

    mode = body.get("mode")
    headers = request.get("header", [])

    content_type = None
    for header in headers:
        if header.get("key", "").lower() == "content-type":
            content_type = header.get("value", "").split(";")[0].strip()
            break

    if mode == "raw":
        raw = body.get("raw", "")
        language = (
            body.get("options", {})
            .get("raw", {})
            .get("language", "")
        )

        if not content_type:
            content_type = (
                "application/json"
                if language == "json"
                else "text/plain"
            )

        media = {}

        try:
            example = json.loads(raw)
            media["schema"] = infer_schema(example)
            media["example"] = example
        except (json.JSONDecodeError, TypeError):
            media["schema"] = (
                {"type": "object"}
                if content_type == "application/json"
                else {"type": "string"}
            )

            if raw and content_type != "application/json":
                media["example"] = raw

        return {
            "required": bool(raw),
            "content": {content_type: media}
        }

    if mode in ("formdata", "urlencoded"):
        properties = {}

        for entry in body.get(mode, []):
            if entry.get("disabled", False):
                continue

            key = entry.get("key")
            if not key:
                continue

            prop = {"type": "string"}

            if entry.get("type") == "file":
                prop["format"] = "binary"

            properties[key] = prop

        media_type = (
            "multipart/form-data"
            if mode == "formdata"
            else "application/x-www-form-urlencoded"
        )

        return {
            "required": True,
            "content": {
                media_type: {
                    "schema": {
                        "type": "object",
                        "properties": properties
                    }
                }
            }
        }

    if mode == "file":
        return {
            "required": True,
            "content": {
                "application/octet-stream": {
                    "schema": {
                        "type": "string",
                        "format": "binary"
                    }
                }
            }
        }

    return None


def get_auth(request, collection):
    auth = request.get("auth")
    if not isinstance(auth, dict):
        auth = collection.get("auth", {})

    if not isinstance(auth, dict):
        return None

    auth_type = auth.get("type")

    if auth_type == "bearer":
        return {
            "name": "bearerAuth",
            "scheme": {
                "type": "http",
                "scheme": "bearer"
            }
        }

    if auth_type == "basic":
        return {
            "name": "basicAuth",
            "scheme": {
                "type": "http",
                "scheme": "basic"
            }
        }

    if auth_type == "apikey":
        values = {
            item.get("key"): item.get("value")
            for item in auth.get("apikey", [])
        }

        location = values.get("in", "header")
        key_name = values.get("key", "X-API-Key")

        if location not in ("header", "query", "cookie"):
            location = "header"

        return {
            "name": "apiKeyAuth",
            "scheme": {
                "type": "apiKey",
                "in": location,
                "name": key_name
            }
        }

    return None


def make_operation(item, request, collection, operation_id):
    method = request.get("method", "GET").lower()
    path, query_params, base_variable = get_url_parts(
        request.get("url", "")
    )

    parameters = []

    for name in re.findall(r"\{([^{}]+)\}", path):
        parameters.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": "string"}
        })

    parameters.extend(query_params)

    for header in request.get("header", []):
        key = header.get("key", "")
        if (
            not key
            or header.get("disabled", False)
            or key.lower() in (
                "content-type",
                "accept",
                "authorization",
                "host",
                "user-agent"
            )
        ):
            continue

        parameters.append({
            "name": key,
            "in": "header",
            "required": False,
            "schema": {"type": "string"}
        })

    unique_parameters = {}
    for parameter in parameters:
        key = (parameter["name"], parameter["in"])
        unique_parameters[key] = parameter

    name = item.get("name", f"{method.upper()} {path}")
    description = get_description(
        request.get("description") or item.get("description")
    )

    first_segment = path.strip("/").split("/")[0]
    tag = (
        "Mail service"
        if base_variable == "url_mail"
        else first_segment.replace("-", " ").title()
    )

    operation = {
        "operationId": operation_id,
        "summary": name,
        "responses": {
            "default": {
                "description": (
                    "Response details are not documented "
                    "in the Postman collection."
                )
            }
        },
        "tags": [tag],
        "x-postman-request-count": 1,
        "x-postman-request-names": [name]
    }

    if description:
        operation["description"] = description

    if unique_parameters:
        operation["parameters"] = list(unique_parameters.values())

    if base_variable:
        operation["x-postman-base-variable"] = base_variable

    request_body = get_request_body(request)
    if request_body:
        operation["requestBody"] = request_body

    auth = get_auth(request, collection)
    if auth:
        operation["security"] = [{auth["name"]: []}]
        return operation, path, method, auth

    return operation, path, method, None


def walk_items(items):
    for item in items or []:
        if "request" in item:
            yield item
        else:
            yield from walk_items(item.get("item", []))


def main():
    data = json.loads(INPUT.read_text(encoding="utf-8-sig"))

    collection = data.get("collection", data)

    paths = {}
    security_schemes = {}
    request_count = 0
    operation_count = 0
    operation_ids = set()

    for item in walk_items(collection.get("item", [])):
        request = item["request"]

        method = request.get("method", "GET").lower()
        raw_url = request.get("url", "")

        path, _, _ = get_url_parts(raw_url)

        base_id = re.sub(
            r"[^a-zA-Z0-9]+",
            "_",
            f"{method}_{path}"
        ).strip("_")

        operation_id = base_id
        suffix = 2

        while operation_id in operation_ids:
            operation_id = f"{base_id}_{suffix}"
            suffix += 1

        operation_ids.add(operation_id)

        operation, path, method, auth = make_operation(
            item,
            request,
            collection,
            operation_id
        )

        request_count += 1

        if auth:
            security_schemes[auth["name"]] = auth["scheme"]

        paths.setdefault(path, {})

        if method in paths[path]:
            existing = paths[path][method]
            existing["x-postman-request-count"] += 1
            existing["x-postman-request-names"].append(
                item.get("name", f"{method.upper()} {path}")
            )

            # Preserve additional parameters from duplicate requests.
            current = existing.setdefault("parameters", [])
            known = {
                (p["name"], p["in"])
                for p in current
            }

            for parameter in operation.get("parameters", []):
                key = (parameter["name"], parameter["in"])
                if key not in known:
                    current.append(parameter)
                    known.add(key)

            continue

        paths[path][method] = operation
        operation_count += 1

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": collection.get("info", {}).get(
                "name", "crAPI API"
            ),
            "version": "1.0.0",
            "description": (
                "OpenAPI specification generated from the "
                "provided Postman collection. "
                "Endpoints and methods are collection-derived. "
                "Response schemas are not inferred."
            )
        },
        "servers": [
            {
                "url": "/",
                "description": (
                    "Relative server URL. Configure the target "
                    "host in the API client."
                )
            }
        ],
        "paths": paths,
        "x-postman-source": "recon/postman_collection.json",
        "x-postman-total-requests": request_count
    }

    if security_schemes:
        spec["components"] = {
            "securitySchemes": security_schemes
        }

    OUTPUT.write_text(
        json.dumps(spec, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("OPENAPI FILE CREATED")
    print("Output:", OUTPUT)
    print("Postman requests:", request_count)
    print("Unique operations:", operation_count)
    print("Unique paths:", len(paths))
    print("Security schemes:", len(security_schemes))


if __name__ == "__main__":
    main()
