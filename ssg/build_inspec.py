from __future__ import absolute_import

import os
import os.path
import json

from .build_yaml import Rule, DocumentationNotComplete
from .jinja import process_file
from .rules import get_rule_dir_id, get_rule_dir_inspecs, find_rule_dirs_in_paths
from . import utils
from . import templates as template_module


def write_inspec_file(content, output_dir, filename):
    with open(os.path.join(output_dir, filename), 'w') as output_file:
        output_file.write(content)


def load_inspec_and_metadata(file_path, local_env_yaml):
    raw_content = process_file(file_path, local_env_yaml)
    metadata = {}
    check_content = []

    for line in raw_content.splitlines():
        if line.startswith('# platform = '):
            _, value = line[2:].split('=', maxsplit=1)
            metadata['platform'] = value.strip()
        else:
            check_content.append(line)

    content = "\n".join(check_content)
    return content, metadata


class InSpecBuilder(object):
    def __init__(self, env_yaml, product_yaml_path, templates_dir, output_dir):
        self.env_yaml = env_yaml
        self.product_yaml_path = product_yaml_path
        self.templates_dir = templates_dir
        self.output_dir = output_dir
        self.already_loaded = {}
        self.template_builder = None

    def _get_guide_dirs(self):
        product_dir = self.env_yaml.get("product_dir", "")
        benchmark_root = utils.required_key(self.env_yaml, "benchmark_root")
        guide_dir = os.path.abspath(os.path.join(product_dir, benchmark_root))
        dirs = [guide_dir]
        add_content_dirs = self.env_yaml.get("additional_content_directories", [])
        for add_content_dir in add_content_dirs:
            dirs.append(os.path.abspath(os.path.join(product_dir, add_content_dir)))
        return dirs

    def _init_template_builder(self):
        if self.template_builder is not None:
            return
        remediations_dir = os.path.join(self.output_dir, "_remediations_unused")
        utils.mkdir_p(remediations_dir)
        self.template_builder = template_module.Builder(
            self.env_yaml, None, self.templates_dir,
            remediations_dir, self.output_dir, None, None)

    def _build_static_inspec_check(self, rule_id, file_path, local_env_yaml):
        if rule_id in self.already_loaded:
            return

        content, metadata = load_inspec_and_metadata(file_path, local_env_yaml)

        product = utils.required_key(self.env_yaml, "product")
        if metadata.get("platform"):
            if not utils.is_applicable_for_product(metadata["platform"], product):
                return

        filename = rule_id + ".rb"
        write_inspec_file(content, self.output_dir, filename)
        metadata['filename'] = filename
        self.already_loaded[rule_id] = metadata

    def _build_templated_inspec_check(self, rule):
        if not rule.is_templated():
            return

        inspec_lang = template_module.LANGUAGES.get("inspec")
        if inspec_lang is None:
            return

        if rule.id_ in self.already_loaded:
            return

        try:
            template_name = rule.get_template_name()
            if template_name not in self.template_builder.templates:
                return

            template = self.template_builder.templates[template_name]
            if inspec_lang not in template.langs:
                return

            raw_content = self.template_builder.get_lang_contents_for_templatable(
                rule, inspec_lang)
        except Exception:
            return

        filename = rule.id_ + ".rb"
        content, metadata = raw_content, {}

        if isinstance(content, str):
            lines = content.splitlines()
            check_lines = []
            for line in lines:
                if line.startswith('# platform = '):
                    _, value = line[2:].split('=', maxsplit=1)
                    metadata['platform'] = value.strip()
                else:
                    check_lines.append(line)
            content = "\n".join(check_lines)

        write_inspec_file(content, self.output_dir, filename)
        metadata['filename'] = filename
        self.already_loaded[rule.id_] = metadata

    def _build_rule(self, rule_dir_path):
        local_env_yaml = dict()
        local_env_yaml.update(self.env_yaml)

        product = utils.required_key(self.env_yaml, "product")
        rule_id = get_rule_dir_id(rule_dir_path)
        rule_path = os.path.join(rule_dir_path, "rule.yml")

        try:
            rule = Rule.from_yaml(rule_path, self.env_yaml)
        except DocumentationNotComplete:
            return

        local_env_yaml['rule_id'] = rule.id_
        local_env_yaml['rule_title'] = rule.title
        local_env_yaml['products'] = {product}

        for _path in get_rule_dir_inspecs(rule_dir_path, product):
            self._build_static_inspec_check(rule_id, _path, local_env_yaml)

        self._build_templated_inspec_check(rule)

    def build(self):
        utils.mkdir_p(self.output_dir)

        guide_paths = self._get_guide_dirs()
        all_rule_dirs = []
        for guide_path in guide_paths:
            if os.path.isdir(guide_path):
                all_rule_dirs.extend(find_rule_dirs_in_paths([guide_path]))

        self._init_template_builder()

        for rule_dir_path in all_rule_dirs:
            self._build_rule(rule_dir_path)

        metadata_path = os.path.join(self.output_dir, "metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(self.already_loaded, f, indent=2, sort_keys=True)
