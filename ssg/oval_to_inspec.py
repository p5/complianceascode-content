"""
Generate InSpec controls from compiled OVAL XML.

Parses the OVAL definitions, tests, objects, and states to produce
equivalent InSpec describe blocks. Each OVAL test type maps to a small
.rb.j2 template in shared/inspec_templates/. This eliminates the need
for per-rule InSpec Jinja files — InSpec is derived from OVAL, the
canonical check definition.
"""

import os
import re
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader


def _local(tag):
    return tag.split("}")[-1] if "}" in tag else tag


def _child_text(elem, local_name):
    for child in elem:
        if _local(child.tag) == local_name:
            return child.text
    return None


def _child_attr(elem, local_name, attr):
    for child in elem:
        if _local(child.tag) == local_name:
            return child.get(attr)
    return None


def _file_state_to_mode(state):
    fields = [
        ("suid", 0o4000), ("sgid", 0o2000), ("sticky", 0o1000),
        ("uread", 0o0400), ("uwrite", 0o0200), ("uexec", 0o0100),
        ("gread", 0o0040), ("gwrite", 0o0020), ("gexec", 0o0010),
        ("oread", 0o0004), ("owrite", 0o0002), ("oexec", 0o0001),
    ]
    mode = 0o7777
    for child in state:
        tag = _local(child.tag)
        for name, bit in fields:
            if tag == name and child.text == "false":
                mode &= ~bit
    return "%04o" % mode


class OVALDocument:
    def __init__(self, oval_path):
        self.tree = ET.parse(oval_path)
        self.root = self.tree.getroot()
        self._index_elements()

    def _index_elements(self):
        self.definitions = {}
        self.tests = {}
        self.objects = {}
        self.states = {}
        self.variables = {}

        for elem in self.root.iter():
            eid = elem.get("id", "")
            tag = _local(elem.tag)

            if tag == "definition":
                self.definitions[eid] = elem
            elif tag.endswith("_test"):
                self.tests[eid] = elem
            elif tag.endswith("_object"):
                self.objects[eid] = elem
            elif tag.endswith("_state"):
                self.states[eid] = elem
            elif tag.endswith("_variable") or tag == "constant_variable":
                self.variables[eid] = elem

    def get_compliance_definitions(self):
        result = {}
        for did, d in self.definitions.items():
            if d.get("class") == "compliance":
                rule_id = did.replace("oval:ssg-", "").replace(":def:1", "")
                result[rule_id] = d
        return result

    def get_test(self, ref):
        return self.tests.get(ref)

    def get_object(self, ref):
        return self.objects.get(ref)

    def get_state(self, ref):
        return self.states.get(ref)

    def resolve_var(self, var_ref):
        var = self.variables.get(var_ref)
        if var is None:
            return None
        for child in var:
            if _local(child.tag) == "literal_component":
                return child.text
        return None

    def get_state_child_value(self, state_child):
        var_ref = state_child.get("var_ref")
        if var_ref:
            return self.resolve_var(var_ref)
        return state_child.text

    def get_test_refs(self, definition):
        refs = []
        for elem in definition.iter():
            if _local(elem.tag) == "criterion":
                ref = elem.get("test_ref")
                if ref:
                    refs.append(ref)
        return refs

    def get_test_object_and_state(self, test_elem):
        obj_ref = state_ref = None
        for child in test_elem:
            tag = _local(child.tag)
            if tag == "object":
                obj_ref = child.get("object_ref")
            elif tag == "state":
                state_ref = child.get("state_ref")
        obj = self.get_object(obj_ref) if obj_ref else None
        state = self.get_state(state_ref) if state_ref else None
        return obj, state

    def get_filter_states(self, obj):
        result = []
        for child in obj:
            if _local(child.tag) == "filter" and child.get("action") == "exclude":
                ref = child.text
                if ref:
                    s = self.get_state(ref)
                    if s is not None:
                        result.append(s)
        return result


PERM_FIELDS = {"suid", "sgid", "sticky", "uread", "uwrite", "uexec",
               "gread", "gwrite", "gexec", "oread", "owrite", "oexec"}


class OVALToInSpec:
    def __init__(self, oval_doc, templates_dir=None):
        self.doc = oval_doc
        if templates_dir is None:
            templates_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "shared", "inspec_templates")
        self.jinja_env = Environment(
            loader=FileSystemLoader(templates_dir),
            keep_trailing_newline=True)

    def _render(self, template_name, **kwargs):
        tmpl = self.jinja_env.get_template(template_name)
        return tmpl.render(**kwargs).strip()

    def convert_definition(self, rule_id, definition):
        test_refs = self.doc.get_test_refs(definition)
        if not test_refs:
            return None
        parts = []
        for ref in test_refs:
            test = self.doc.get_test(ref)
            if test is None:
                continue
            result = self._convert_test(test)
            if result:
                parts.append(result)
        if not parts:
            return None
        return "\n\n".join(parts) + "\n"

    def _convert_test(self, test):
        tag = _local(test.tag)
        handler = {
            "file_test": self._file_test,
            "rpminfo_test": self._rpminfo_test,
            "textfilecontent54_test": self._textfilecontent_test,
            "sysctl_test": self._sysctl_test,
            "systemdunitproperty_test": self._systemd_test,
            "systemdunitdependency_test": self._systemd_dep_test,
            "partition_test": self._partition_test,
            "selinuxboolean_test": self._selinux_bool_test,
            "shadow_test": self._shadow_test,
            "symlink_test": self._symlink_test,
            "environmentvariable58_test": self._env_var_test,
            "password_test": self._password_test,
            "process58_test": self._process_test,
            "xmlfilecontent_test": self._xmlfilecontent_test,
            "rpmverifyfile_test": self._rpmverify_test,
            "variable_test": self._variable_test,
            "family_test": self._skip_test,
            "uname_test": self._skip_test,
            "interface_test": self._skip_test,
            "inetlisteningservers_test": self._skip_test,
            "selinuxsecuritycontext_test": self._skip_test,
        }.get(tag)
        if handler:
            return handler(test)
        return self._render("unsupported.rb.j2", test_type=tag)

    # -- File checks --

    def _file_target(self, obj):
        fp = _child_text(obj, "filepath")
        if fp:
            return fp
        p = _child_text(obj, "path")
        if p:
            return p.rstrip("/") + "/"
        return None

    def _file_test(self, test):
        existence = test.get("check_existence", "at_least_one_exists")
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        target = self._file_target(obj)
        if not target:
            return None

        if existence == "none_exist":
            for fs in self.doc.get_filter_states(obj):
                children = {_local(c.tag): c for c in fs}
                if PERM_FIELDS & set(children.keys()):
                    return self._render("file_permissions.rb.j2",
                                        filepath=target, mode=_file_state_to_mode(fs))
                if "user_id" in children:
                    uid = self.doc.get_state_child_value(children["user_id"])
                    if uid is not None:
                        return self._render("file_owner.rb.j2", filepath=target, uid=uid)
                if "group_id" in children:
                    gid = self.doc.get_state_child_value(children["group_id"])
                    if gid is not None:
                        return self._render("file_group.rb.j2", filepath=target, gid=gid)
            return self._render("file_not_exists.rb.j2", filepath=target)

        if state is not None:
            children = {_local(c.tag): c for c in state}
            if PERM_FIELDS & set(children.keys()):
                return self._render("file_permissions.rb.j2",
                                    filepath=target, mode=_file_state_to_mode(state))
            if "user_id" in children:
                uid = self.doc.get_state_child_value(children["user_id"])
                if uid is not None:
                    return self._render("file_owner.rb.j2", filepath=target, uid=uid)
            if "group_id" in children:
                gid = self.doc.get_state_child_value(children["group_id"])
                if gid is not None:
                    return self._render("file_group.rb.j2", filepath=target, gid=gid)

        return self._render("file_exists.rb.j2", filepath=target)

    # -- Package checks --

    def _rpminfo_test(self, test):
        existence = test.get("check_existence", "at_least_one_exists")
        obj, _ = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        name = _child_text(obj, "name")
        if not name:
            return None
        if existence == "none_exist":
            return self._render("package_removed.rb.j2", name=name)
        return self._render("package_installed.rb.j2", name=name)

    # -- Text file content checks --

    def _textfilecontent_test(self, test):
        existence = test.get("check_existence", "at_least_one_exists")
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        filepath = _child_text(obj, "filepath")
        path = _child_text(obj, "path")
        filename = _child_text(obj, "filename")
        pattern = _child_text(obj, "pattern")
        if filepath:
            target = filepath
        elif path and filename:
            target = path.rstrip("/") + "/" + filename
        else:
            return None
        if not pattern:
            return None
        escaped = pattern.replace("/", "\\/")
        if existence == "none_exist":
            return self._render("textfilecontent_absent.rb.j2",
                                filepath=target, pattern=escaped)
        return self._render("textfilecontent.rb.j2",
                            filepath=target, pattern=escaped)

    # -- Sysctl checks --

    def _sysctl_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        name = _child_text(obj, "name")
        if not name:
            return None
        if state is not None:
            value = _child_text(state, "value")
            op = _child_attr(state, "value", "operation") or "equals"
            if value:
                if op == "pattern match":
                    return self._render("sysctl_regex.rb.j2",
                                        name=name, pattern=value.replace("/", "\\/"))
                return self._render("sysctl.rb.j2", name=name, value=value)
        return self._render("sysctl.rb.j2", name=name, value="")

    # -- Systemd checks --

    def _extract_service_name(self, unit_raw):
        unit = re.sub(r"^\^|\$$", "", unit_raw).replace("\\.", ".")
        m = re.match(r"^(\w[\w-]*)\.\(?(service|socket)", unit)
        if m:
            return m.group(1)
        return unit.split(".")[0] if "." in unit else unit

    def _systemd_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        unit_raw = _child_text(obj, "unit")
        prop = _child_text(obj, "property")
        if not unit_raw or not prop:
            return None
        name = self._extract_service_name(unit_raw)
        if state is not None:
            value = _child_text(state, "value")
            op = _child_attr(state, "value", "operation") or "equals"
            if prop == "ActiveState":
                if value in ("inactive", "inactive|failed") or op == "pattern match":
                    return self._render("service_disabled.rb.j2", name=name)
                if value == "active":
                    return self._render("service_enabled.rb.j2", name=name)
            if prop == "UnitFileState":
                if value in ("disabled", "masked"):
                    return self._render("service_disabled.rb.j2", name=name)
                if value in ("enabled", "enabled-runtime"):
                    return self._render("service_enabled.rb.j2", name=name)
            if prop == "LoadState" and value == "not-found":
                return self._render("service_not_installed.rb.j2", name=name)
        return self._render("service_disabled.rb.j2", name=name)

    def _systemd_dep_test(self, test):
        obj, _ = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        unit = _child_text(obj, "unit")
        if not unit:
            return None
        name = self._extract_service_name(unit)
        return self._render("service_disabled.rb.j2", name=name)

    # -- Mount/partition checks --

    def _partition_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        mount_point = _child_text(obj, "mount_point")
        if not mount_point:
            return None
        options = []
        if state is not None:
            for child in state:
                if _local(child.tag) == "mount_options" and child.text:
                    options.append(child.text)
        if options:
            return "\n\n".join(
                self._render("mount_option.rb.j2", mount_point=mount_point, option=opt)
                for opt in options)
        return self._render("mount_option.rb.j2", mount_point=mount_point, option="")

    # -- SELinux boolean checks --

    def _selinux_bool_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        name = _child_text(obj, "name")
        if not name:
            return None
        expected = "on"
        if state is not None:
            val = _child_text(state, "current_status")
            if val == "false":
                expected = "off"
        return self._render("selinux_boolean.rb.j2", name=name, expected=expected)

    # -- Shadow checks --

    def _shadow_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if state is None:
            return None
        checks = []
        for child in state:
            tag = _local(child.tag)
            val = child.text
            op = child.get("operation", "equals")
            if tag == "max_days" and val:
                comp = "<=" if "less than" in op else "=="
                checks.append({"field": "max_days.uniq", "op": comp, "value": val})
            elif tag == "min_days" and val:
                checks.append({"field": "min_days.uniq", "op": ">=", "value": val})
        if not checks:
            return None
        return self._render("shadow.rb.j2", checks=checks)

    # -- Symlink checks --

    def _symlink_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None or state is None:
            return None
        filepath = _child_text(obj, "filepath")
        if not filepath:
            return None
        target = _child_text(state, "canonical_path")
        if not target:
            return None
        return self._render("symlink_target.rb.j2",
                            filepath=filepath,
                            target_pattern=target.replace("/", "\\/"))

    # -- Environment variable checks --

    def _env_var_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None or state is None:
            return None
        name = _child_text(obj, "name")
        if not name:
            return None
        pattern = _child_text(state, "value")
        if not pattern:
            return None
        return self._render("env_variable.rb.j2",
                            name=name,
                            bad_pattern=pattern.replace("/", "\\/"))

    # -- Password checks --

    def _password_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if state is None:
            return None
        pattern = _child_text(state, "password")
        if not pattern:
            return None
        return self._render("password_shadowed.rb.j2",
                            pattern=pattern.replace("/", "\\/"))

    # -- Process checks --

    def _process_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        cmd = _child_text(obj, "command_line")
        if not cmd:
            return None
        return self._render("process_running.rb.j2",
                            command_pattern=cmd.replace("/", "\\/"))

    # -- XML file content checks --

    def _xmlfilecontent_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        path = _child_text(obj, "path")
        filename = _child_text(obj, "filename")
        filepath = _child_text(obj, "filepath")
        xpath = _child_text(obj, "xpath")
        if filepath:
            target = filepath
        elif path and filename:
            target = path.rstrip("/") + "/" + filename
        else:
            return None
        if not xpath:
            return None
        return self._render("xmlfilecontent.rb.j2",
                            filepath=target, xpath=xpath)

    # -- RPM verify checks --

    def _rpmverify_test(self, test):
        obj, state = self.doc.get_test_object_and_state(test)
        if obj is None:
            return None
        filepath = _child_text(obj, "filepath")
        if not filepath:
            filepath = "^/(bin|sbin|lib|lib64|usr)/.+"
        return self._render("rpm_verify.rb.j2",
                            filepath_pattern=filepath.replace("/", "\\/"))

    # -- Variable test (internal OVAL logic, skip) --

    def _variable_test(self, test):
        return None

    # -- Tests that can't map to InSpec (platform/arch checks) --

    def _skip_test(self, test):
        return None

    def convert_all(self):
        results = {}
        for rule_id, definition in self.doc.get_compliance_definitions().items():
            code = self.convert_definition(rule_id, definition)
            if code and "not yet mapped" not in code:
                results[rule_id] = code
        return results


def generate_inspec_from_oval(oval_path, templates_dir=None):
    doc = OVALDocument(oval_path)
    converter = OVALToInSpec(doc, templates_dir)
    return converter.convert_all()
