#!/usr/bin/python3
"""
Build InSpec checks from compiled OVAL XML.

Reads the product's compiled OVAL file and generates InSpec .rb checks
plus metadata.json. Each OVAL test type maps to a pattern template in
shared/inspec_templates/.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ssg.build_inspec import build_inspec_checks


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--oval-file", required=True,
        help="Path to compiled OVAL XML (e.g., ssg-rhel9-oval.xml)."
    )
    p.add_argument(
        "--output", required=True,
        help="Output directory for InSpec .rb checks and metadata.json."
    )
    p.add_argument(
        "--templates-dir",
        help="Path to InSpec pattern templates (default: shared/inspec_templates)."
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    count = build_inspec_checks(args.oval_file, args.output, args.templates_dir)
    print("Generated %d InSpec checks" % count)
