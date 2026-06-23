#!/usr/bin/python3
"""
build_inspec_profile.py assembles individual InSpec .rb check files into
valid InSpec profile directories, one per XCCDF profile.

Output:
  <build>/ssg-<product>-inspec-<profile>/
    inspec.yml
    controls/
      <rule_id>.rb
"""

import argparse
import json
import os
import re
import shutil

import ssg.build_yaml
import ssg.environment
import ssg.yaml
from ssg.utils import mkdir_p


SEVERITY_TO_IMPACT = {
    "high": 0.7,
    "medium": 0.5,
    "low": 0.3,
    "unknown": 0.5,
}


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
        "--inspec-dir", required=True,
        help="Directory containing InSpec .rb check files and metadata.json."
    )
    p.add_argument(
        "--resolved-base", required=True,
        help="Base directory with resolved rule and profile YAMLs."
    )
    p.add_argument(
        "--output-dir", required=True,
        help="Output directory for assembled InSpec profiles."
    )
    return p.parse_args()


def load_metadata(inspec_dir):
    metadata_path = os.path.join(inspec_dir, "metadata.json")
    if not os.path.exists(metadata_path) or os.path.getsize(metadata_path) == 0:
        return {}
    with open(metadata_path, 'r') as f:
        return json.load(f)


def load_profiles(resolved_base):
    profiles = {}
    profiles_dir = os.path.join(resolved_base, "profiles")
    if not os.path.isdir(profiles_dir):
        return profiles
    for fname in sorted(os.listdir(profiles_dir)):
        if not fname.endswith(".profile"):
            continue
        profile_path = os.path.join(profiles_dir, fname)
        profile_data = ssg.yaml.open_raw(profile_path)
        profile_id = profile_data.get("id_", fname.replace(".profile", ""))
        profiles[profile_id] = profile_data
    return profiles


def load_rule_metadata(resolved_base, rule_id):
    rule_path = os.path.join(resolved_base, "rules", rule_id + ".json")
    if not os.path.exists(rule_path):
        rule_path = os.path.join(resolved_base, "rules", rule_id + ".yml")
    if not os.path.exists(rule_path):
        return None
    if rule_path.endswith(".json"):
        with open(rule_path, 'r') as f:
            return json.load(f)
    return ssg.yaml.open_raw(rule_path)


def wrap_control(rule_id, check_content, rule_data):
    severity = "medium"
    title = rule_id
    description = ""

    if rule_data:
        severity = rule_data.get("severity", "medium")
        title = rule_data.get("title", rule_id)
        description = re.sub(r'<[^>]+>', '', rule_data.get("description", ""))
        description = description.replace('\n', ' ').strip()

    impact = SEVERITY_TO_IMPACT.get(severity, 0.5)

    title_escaped = title.replace("\\", "\\\\").replace('"', '\\"')
    desc_escaped = description.replace("\\", "\\\\").replace('"', '\\"')

    lines = []
    lines.append("control '%s' do" % rule_id)
    lines.append('  title "%s"' % title_escaped)
    lines.append('  desc "%s"' % desc_escaped)
    lines.append("  impact %.1f" % impact)
    lines.append("  tag severity: '%s'" % severity)

    if rule_data:
        identifiers = rule_data.get("identifiers", {})
        for id_type, id_val in sorted(identifiers.items()):
            if id_val:
                lines.append("  tag %s: '%s'" % (id_type, id_val))

        refs = rule_data.get("references", {})
        for ref_type, ref_val in sorted(refs.items()):
            if ref_val:
                tag_name = ref_type if ref_type.isidentifier() else "'%s'" % ref_type
                if isinstance(ref_val, list):
                    items = ", ".join("'%s'" % v for v in ref_val)
                    lines.append("  tag %s: [%s]" % (tag_name, items))
                else:
                    lines.append("  tag %s: '%s'" % (tag_name, str(ref_val).replace("'", "\\'")))

    for line in check_content.strip().splitlines():
        lines.append("  " + line)
    lines.append("end")

    return "\n".join(lines) + "\n"


def build_profile(profile_id, profile_data, metadata, inspec_dir,
                  resolved_base, output_dir, product):
    profile_dir = os.path.join(output_dir, "ssg-%s-inspec-%s" % (product, profile_id))
    controls_dir = os.path.join(profile_dir, "controls")
    mkdir_p(controls_dir)

    selections = profile_data.get("selections", profile_data.get("selected", []))
    selections = [s for s in selections if not s.startswith("var_") and "=" not in s]
    if not selections:
        return

    rules_written = 0
    for rule_id in selections:
        if rule_id not in metadata:
            continue
        src_file = os.path.join(inspec_dir, metadata[rule_id]["filename"])
        if not os.path.exists(src_file):
            continue

        with open(src_file, 'r') as f:
            check_content = f.read()

        rule_data = load_rule_metadata(resolved_base, rule_id)
        wrapped = wrap_control(rule_id, check_content, rule_data)

        dst_file = os.path.join(controls_dir, rule_id + ".rb")
        with open(dst_file, 'w') as f:
            f.write(wrapped)
        rules_written += 1

    if rules_written == 0:
        shutil.rmtree(profile_dir, ignore_errors=True)
        return

    profile_title = profile_data.get("title", profile_id)
    inspec_yml = {
        "name": "ssg-%s-%s" % (product, profile_id),
        "title": profile_title,
        "maintainer": "ComplianceAsCode",
        "license": "Apache-2.0",
        "summary": profile_data.get("description", profile_title),
        "version": "0.1.0",
        "supports": [{"os-family": "unix"}],
    }

    summary = re.sub(r'\s+', ' ',
                     inspec_yml["summary"].replace('\n', ' ').strip())
    if len(summary) > 120:
        summary = summary[:120] + "..."

    inspec_yml_out = {
        "name": inspec_yml["name"],
        "title": inspec_yml["title"],
        "maintainer": inspec_yml["maintainer"],
        "copyright": "ComplianceAsCode contributors",
        "copyright_email": "scap-security-guide@lists.fedorahosted.org",
        "license": inspec_yml["license"],
        "summary": summary,
        "version": inspec_yml["version"],
        "supports": inspec_yml["supports"],
    }

    yml_path = os.path.join(profile_dir, "inspec.yml")
    try:
        import yaml
        with open(yml_path, 'w') as f:
            yaml.dump(inspec_yml_out, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        with open(yml_path, 'w') as f:
            for key, val in inspec_yml_out.items():
                if isinstance(val, list):
                    f.write("%s:\n" % key)
                    for item in val:
                        if isinstance(item, dict):
                            first = True
                            for k, v in item.items():
                                prefix = "  - " if first else "    "
                                f.write("%s%s: %s\n" % (prefix, k, v))
                                first = False
                        else:
                            f.write("  - %s\n" % item)
                else:
                    f.write("%s: %s\n" % (key, val))


if __name__ == "__main__":
    args = parse_args()
    env_yaml = ssg.environment.open_environment(
        args.build_config_yaml, args.product_yaml)

    product = env_yaml["product"]
    metadata = load_metadata(args.inspec_dir)

    if not metadata:
        exit(0)

    profiles = load_profiles(args.resolved_base)
    mkdir_p(args.output_dir)

    for profile_id, profile_data in profiles.items():
        build_profile(
            profile_id, profile_data, metadata,
            args.inspec_dir, args.resolved_base,
            args.output_dir, product)
