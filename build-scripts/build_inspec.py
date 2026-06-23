#!/usr/bin/python3
"""
build_inspec.py generates InSpec check content from rule definitions.

Output artifacts:
  - <build>/<product>/checks/inspec/metadata.json
  - <build>/<product>/checks/inspec/<rule_id>.rb

metadata.json maps rule IDs to their InSpec check filenames and platform
applicability.
"""

import argparse
import ssg.build_inspec
import ssg.environment
import ssg.jinja
from ssg.utils import mkdir_p


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--build-config-yaml", required=True,
        help="YAML file with build configuration."
    )
    p.add_argument(
        "--product-yaml", required=True,
        help="YAML file with product information."
    )
    p.add_argument(
        "--templates-dir", required=True,
        help="Path to shared templates directory."
    )
    p.add_argument(
        "--output", required=True,
        help="Output directory for InSpec checks."
    )
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    env_yaml = ssg.environment.open_environment(
        args.build_config_yaml, args.product_yaml)
    ssg.jinja.initialize(env_yaml)

    mkdir_p(args.output)

    builder = ssg.build_inspec.InSpecBuilder(
        env_yaml, args.product_yaml,
        args.templates_dir, args.output)
    builder.build()
