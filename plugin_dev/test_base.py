from __future__ import annotations
import logging
import os
import subprocess
import ast
from keeper_secrets_manager_core.dto.dtos import Record
from keeper_secrets_manager_core.utils import generate_uid_bytes
from colorama import Fore, Style
from typing import List, Dict, Any, Optional


class MockRecord(Record):

    # Don't call super
    def __init__(self,
                 title: Optional[str] = "SaaS Config",
                 record_type: str = "login",
                 uid: Optional[str] = None,
                 fields: Optional[List[dict]] = None,
                 custom: Optional[List[dict]] = None):

        if uid is None:
            uid = generate_uid_bytes()

        self.uid = uid
        self.title = title
        self.type = record_type
        self.files = []

        if fields is None:
            fields = []

        self.dict = {
            "fields": fields,
            "custom": custom
        }


class WorkflowBase:

    def __init__(self):

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('{asctime}  {process:>5}  {name:<22}  {levelname}: {message}', style='{')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.base_dir = os.environ.get("PROJECT_BASE", os.getcwd())

    def changed_integrations(self, ref: str) -> List[str]:

        self.logger.info(f"Getting diff for {ref}")

        #           git diff --name-status origin/${{ github.event.pull_request.base.ref }}...HEAD

        # subprocess.run(["git", "fetch", "origin", ref], capture_output=True, text=True)
        cmd = f"git --no-pager diff --name-status origin/{ref}...HEAD"
        self.logger.debug(cmd)
        process = subprocess.run(["bash", "-c", cmd],
                                 capture_output=True, text=True)
        if process.returncode != 0:
            self.logger.debug(f"{Fore.WHITE}{process.stdout}{Style.RESET_ALL}")
            if process.stderr is not None and process.stderr != "":
                self.logger.debug(f"{Fore.RED}{process.stderr}{Style.RESET_ALL}")
            raise Exception(f"Could not diff {ref}")

        changed = []

        for row in process.stdout.split("\n"):
            row = row.strip()
            if row == "":
                break
            status_and_file = row.split("\t", maxsplit=1)
            status = status_and_file[0].strip()
            file = status_and_file[1].strip()
            if file.startswith("integrations") is False:
                continue

            file_new_file = file.split("\t", maxsplit=1)
            file = file_new_file[0].strip()

            parts = file.split("/", maxsplit=2)

            # Make sure the file is a directory
            integration_dir = os.path.join(self.base_dir, "integrations", parts[1])
            if os.path.isdir(integration_dir) is False:
                continue

            if status.startswith("D") is False:
                if parts[1] not in changed:
                    changed.append(parts[1])

        self.logger.info(f"  check: {changed}")

        return changed


class PluginVisitor(ast.NodeVisitor):
    def __init__(self):
        self._requirements: List[Dict[str, Any]] = []
        self.current_class: Optional[str] = None
        self.name = None
        self.summary = None
        self.readme = None
        self.author = None
        self.email = None
        self.schema = []

    @property
    def requirements(self):
        ret = []
        for item in self._requirements:
            ret += item['values']
        return ret

    def visit_ClassDef(self, node: ast.ClassDef):
        if node.name == "SaasPlugin":
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "name":
                            value = stmt.value
                            if isinstance(value, ast.Constant):
                                self.name = value.value
                        elif isinstance(target, ast.Name) and target.id == "summary":
                            value = stmt.value
                            if isinstance(value, ast.Constant):
                                self.summary = value.value
                        elif isinstance(target, ast.Name) and target.id == "readme":
                            value = stmt.value
                            if isinstance(value, ast.Constant):
                                self.readme = value.value
                        elif isinstance(target, ast.Name) and target.id == "author":
                            value = stmt.value
                            if isinstance(value, ast.Constant):
                                self.author = value.value
                        elif isinstance(target, ast.Name) and target.id == "email":
                            value = stmt.value
                            if isinstance(value, ast.Constant):
                                self.email = value.value

        prev_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev_class

    @staticmethod
    def _extract_saas_config_items(elts):
        config_items = []

        def extract_value(val):
            if isinstance(val, ast.Constant):
                return val.value
            elif isinstance(val, ast.List):
                return [extract_value(e) for e in val.elts]
            elif isinstance(val, ast.Call):
                if getattr(val.func, 'id', '') == "SaasConfigEnum":
                    enum_dict = {}
                    for kw in val.keywords:
                        enum_dict[kw.arg] = extract_value(kw.value)
                    return enum_dict
            return None  # or raise or log unhandled case

        for item in elts:
            if isinstance(item, ast.Call) and getattr(item.func, 'id', '') == "SaasConfigItem":
                item_dict = {}
                for kw in item.keywords:
                    item_dict[kw.arg] = extract_value(kw.value)
                config_items.append(item_dict)

        return config_items

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if node.name == "config_schema":
            assigned_lists = {}

            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    if isinstance(stmt.value, ast.List):
                        list_items = self._extract_saas_config_items(stmt.value.elts)
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                assigned_lists[target.id] = list_items
                if isinstance(stmt, ast.Return):
                    if isinstance(stmt.value, ast.List):
                        self.schema.extend(self._extract_saas_config_items(stmt.value.elts))
                    elif isinstance(stmt.value, ast.Name):
                        var_name = stmt.value.id
                        self.schema.extend(assigned_lists.get(var_name, []))

        elif node.name == "requirements":
            is_class_method = any(
                isinstance(decorator, ast.Name) and decorator.id == "classmethod"
                for decorator in node.decorator_list
            )
            if not is_class_method:
                return

            # Look for return statements returning a list of strings
            for stmt in node.body:
                if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.List):
                    elements = []
                    for elt in stmt.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            elements.append(elt.value)
                    self._requirements.append({
                        "class": self.current_class,
                        "method": node.name,
                        "values": elements
                    })

        self.generic_visit(node)







