from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

LOCAL_PREFIXES = ("file:", "path+file:")
LOCAL_PATH_MARKERS = ("file://", "/home/runner/", "\\home\\runner\\", "D:/a/", "D:\\a\\")


def _is_local_url(value: str) -> bool:
    return unquote(value).startswith(LOCAL_PREFIXES)


def _portable_purl(purl: str) -> str:
    before_fragment, separator, fragment = purl.partition("#")
    without_query, query_separator, query = before_fragment.partition("?")
    if not query_separator:
        return purl

    kept: list[str] = []
    for parameter in query.split("&"):
        key, _, value = parameter.partition("=")
        if key == "download_url" and _is_local_url(value):
            continue
        kept.append(parameter)

    normalized = without_query
    if kept:
        normalized += "?" + "&".join(kept)
    if separator:
        normalized += "#" + fragment
    return normalized


def _normalize_component(component: dict[str, Any], ref_map: dict[str, str]) -> None:
    purl = component.get("purl")
    if isinstance(purl, str):
        component["purl"] = _portable_purl(purl)

    old_ref = component.get("bom-ref")
    if isinstance(old_ref, str) and old_ref.startswith("path+file:"):
        if not isinstance(purl, str) or not purl.startswith("pkg:"):
            raise ValueError(f"local component has no package URL: {old_ref}")
        new_ref = _portable_purl(purl)
        ref_map[old_ref] = new_ref
        component["bom-ref"] = new_ref

    references = component.get("externalReferences")
    if isinstance(references, list):
        kept = [
            reference
            for reference in references
            if not (isinstance(reference, dict) and isinstance(reference.get("url"), str) and _is_local_url(reference["url"]))
        ]
        if kept:
            component["externalReferences"] = kept
        else:
            component.pop("externalReferences", None)

    children = component.get("components")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                _normalize_component(child, ref_map)


def _normalize_dependencies(document: dict[str, Any], ref_map: dict[str, str]) -> None:
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        return

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        ref = dependency.get("ref")
        if isinstance(ref, str):
            if ref in ref_map:
                dependency["ref"] = ref_map[ref]
            elif ref.startswith("path+file:"):
                raise ValueError(f"dependency references an unknown local component: {ref}")

        depends_on = dependency.get("dependsOn")
        if isinstance(depends_on, list):
            for index, child_ref in enumerate(depends_on):
                if isinstance(child_ref, str) and child_ref in ref_map:
                    depends_on[index] = ref_map[child_ref]
                elif isinstance(child_ref, str) and child_ref.startswith("path+file:"):
                    raise ValueError(f"dependency references an unknown local component: {child_ref}")


def _find_local_path(value: Any, path: str = "$") -> str | None:
    if isinstance(value, str):
        if value.startswith("path+file:") or any(marker in value for marker in LOCAL_PATH_MARKERS):
            return f"{path}: {value}"
        return None
    if isinstance(value, list):
        for index, item in enumerate(value):
            found = _find_local_path(item, f"{path}[{index}]")
            if found is not None:
                return found
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            found = _find_local_path(item, f"{path}.{key}")
            if found is not None:
                return found
    return None


def normalize_document(document: dict[str, Any]) -> dict[str, Any]:
    ref_map: dict[str, str] = {}
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        component = metadata.get("component")
        if isinstance(component, dict):
            _normalize_component(component, ref_map)

    components = document.get("components")
    if isinstance(components, list):
        for component in components:
            if isinstance(component, dict):
                _normalize_component(component, ref_map)

    _normalize_dependencies(document, ref_map)

    local_path = _find_local_path(document)
    if local_path is not None:
        raise ValueError(f"SBOM still contains a build-host path: {local_path}")
    return document


def normalize_sbom(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("SBOM root must be a JSON object")
    normalized = normalize_document(document)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(normalized, indent=2, ensure_ascii=False) + "\n")
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove build-host paths from a CycloneDX JSON SBOM")
    parser.add_argument("sbom", type=Path)
    args = parser.parse_args()
    try:
        normalize_sbom(args.sbom)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
