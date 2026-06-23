"""
Generate InSpec checks from compiled OVAL XML.

Replaces the template-based approach. InSpec is derived from OVAL —
the canonical check definition — so there are no per-template InSpec
files to maintain. Each OVAL test type maps to a small .rb.j2 pattern
template in shared/inspec_templates/.
"""

import json
import os

from . import utils
from .oval_to_inspec import generate_inspec_from_oval


def build_inspec_checks(oval_path, output_dir, templates_dir=None):
    utils.mkdir_p(output_dir)
    results = generate_inspec_from_oval(oval_path, templates_dir)

    metadata = {}
    for rule_id, code in results.items():
        filename = rule_id + ".rb"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w") as f:
            f.write(code)
        metadata[rule_id] = {"filename": filename}

    metadata_path = os.path.join(output_dir, "metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2, sort_keys=True)

    return len(results)
