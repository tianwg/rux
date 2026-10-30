#!/usr/bin/env python3
"""Write rux's API catalog from this server's field schemas and wording.

`api-help.schema.json` and `block-creators.schema.json` list the methods
this process implements: argument names, result fields, and the JSON Schema
constraints the handlers enforce. They contain no description text.
`wording.json` is rux's own one-line wording. Protocol identifiers such as
`com.superlogical.terminal` stay, because clients send them on the wire.

Run from anywhere:

    python3 crates/rux-server/catalog/generate.py

The files under `assets/` are the output embedded by `include_str!`.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT.parent / "assets"


def load(name):
    with (ROOT / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def require(mapping, key, where):
    try:
        return mapping[key]
    except KeyError:
        sys.exit(f"missing wording for {where} {key}")


def apply_help(doc, wording):
    seen_methods = set()
    for method in doc["methods"]:
        name = method["name"]
        seen_methods.add(name)
        method["description"] = require(wording["methods"], name, "method")
    missing = set(wording["methods"]) - seen_methods
    if missing:
        sys.exit("wording has unknown methods: " + ", ".join(sorted(missing)))

    seen_blocks = set()
    seen_actions = set()
    for block in doc["block_types"]:
        creator = block["creator"]
        for method in block["methods"]:
            key = f"{creator}.{method['name']}"
            seen_blocks.add(key)
            method["description"] = require(wording["block_methods"], key, "block method")
            for action in method.get("actions", []):
                seen_actions.add(key)
                text = require(wording["actions"], key, "action")
                action["title"] = text["title"]
                action["description"] = text["description"]
    return doc, seen_blocks, seen_actions


def apply_creators(doc, wording):
    seen_creators = set()
    seen_flavors = set()
    seen_blocks = set()
    seen_actions = set()
    for creator in doc["creators"]:
        name = creator["name"]
        seen_creators.add(name)
        text = require(wording["creators"], name, "creator")
        creator["title"] = text["title"]
        creator["description"] = text["description"]
        for flavor in creator.get("flavors", []):
            flavor_id = flavor["flavor"]
            seen_flavors.add(flavor_id)
            text = require(wording["flavors"], flavor_id, "flavor")
            flavor["title"] = text["title"]
            flavor["description"] = text["description"]
        methods = creator.get("api", {}).get("methods", {})
        for method_name, method in methods.items():
            key = f"{name}.{method_name}"
            seen_blocks.add(key)
            method["description"] = require(wording["block_methods"], key, "creator method")
            for action in method.get("actions", []):
                seen_actions.add(key)
                text = require(wording["actions"], key, "creator action")
                action["title"] = text["title"]
                action["description"] = text["description"]
    for label, seen, expected in (
        ("creators", seen_creators, wording["creators"]),
        ("flavors", seen_flavors, wording["flavors"]),
    ):
        missing = set(expected) - seen
        if missing:
            sys.exit(f"creator catalog is missing {label}: " + ", ".join(sorted(missing)))
    return doc, seen_blocks, seen_actions


def dump(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path} ({len(text)} bytes)")


def main():
    wording = load("wording.json")
    help_doc, help_blocks, help_actions = apply_help(load("api-help.schema.json"), wording)
    creators, creator_blocks, creator_actions = apply_creators(
        load("block-creators.schema.json"), wording
    )
    for label, seen, expected in (
        ("block methods", help_blocks | creator_blocks, wording["block_methods"]),
        ("actions", help_actions | creator_actions, wording["actions"]),
    ):
        missing = set(expected) - seen
        extra = seen - set(expected)
        if missing or extra:
            sys.exit(
                f"{label} wording does not match the schemas: "
                f"missing={sorted(missing)} extra={sorted(extra)}"
            )
    dump(ASSETS / "api-help.json", help_doc)
    dump(ASSETS / "block-creators.json", creators)


if __name__ == "__main__":
    main()
