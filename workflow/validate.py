#!python

"""
Goal of this script is to make sure the integrations are formatted correctly.
"""

import logging
import os
import yaml
import ast

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("Validator")


class PluginValidator(ast.NodeVisitor):

    def __init__(self):
        super().__init__()

        self.schema = []
        self.has_schema_method = False
        self.has_change_password = False

    def visit_FunctionDef(self, node):
        if node.name == "config_schema":
            self.has_schema_method = True
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
        elif node.name == "change_password":
            self.has_change_password = True

        self.generic_visit(node)  # Continue visiting the body

    @staticmethod
    def _extract_saas_config_items(elts):
        config_items = []
        for item in elts:
            if isinstance(item, ast.Call) and getattr(item.func, 'id', '') == "SaasConfigItem":
                item_dict = {}
                for kw in item.keywords:
                    val = kw.value
                    if isinstance(val, ast.Constant):
                        item_dict[kw.arg] = val.value
                    elif isinstance(val, ast.NameConstant):
                        item_dict[kw.arg] = val.value
                config_items.append(item_dict)
        return config_items


base_dir = os.environ.get("PROJECT_BASE", os.getcwd())
entries = os.listdir(os.path.join(base_dir, "integrations"))

package_dict = {}

# Load in plugins from this repo.
logger.info(f"Checking plugins from repo in {base_dir}, {os.getcwd()}")
for entry in entries:
    logger.debug(f"  * {entry}")

    plugin_file = os.path.join(base_dir, "integrations", entry, f"{entry}.py")
    if os.path.exists(plugin_file) is False:
        raise ValueError(f"The python file '{entry}.py' file is missing for plugin {entry}")

    with open(plugin_file, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
        finder = PluginValidator()
        finder.visit(tree)
        if len(finder.schema) == 0:
            raise ValueError(f"The python file '{entry}.py' file is missing the config_schema method")

    meta_file = os.path.join(base_dir, "integrations", entry, "meta.yml")
    if os.path.exists(meta_file) is True:
        with open(meta_file, 'r') as fh:
            data = yaml.safe_load(fh)
            name = data.get("name")
            author = data.get("author")
            email = data.get("email")
            summary = data.get("summary")
            if name is None or name == "":
                ValueError(f"  !! the meta.yml file is missing the 'name' for {entry}")
            if author is None or author == "":
                ValueError(f"  !! the meta.yml file is missing the 'author' for {entry}")
            if email is None or email == "":
                ValueError(f"  !! the meta.yml file is missing the 'email' for {entry}")
            if summary is None or summary == "":
                ValueError(f"  !! the meta.yml file is missing the 'summary' for {entry}")
            fh.close()
    else:
        raise ValueError(f"The 'meta.yml' file is missing for plugin {entry}")

    logger.info("     :) is valid")
