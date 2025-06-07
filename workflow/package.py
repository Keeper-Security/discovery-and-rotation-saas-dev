#!python

import logging
import os
import yaml
import ast
import sys

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info("Starting packager")

base_dir = os.environ.get("PROJECT_BASE", os.getcwd())
entries = os.listdir(os.path.join(base_dir, "integrations"))

sys.path.append(base_dir)
logger.debug(f"Path = {sys.path}")

package_dict = {}


class PluginValidator(ast.NodeVisitor):

    def __init__(self):
        super().__init__()

        self.schema = []

    def visit_FunctionDef(self, node):
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


# Load in the builtin SaaS plugins from KDNRM
logger.info("Loading built in plugins.")
with open(os.path.join(base_dir, "catalog", "builtin.yml"), 'r') as fh:
    datas = yaml.safe_load_all(fh)
    for data in datas:
        data["summary"] = data.get("summary").strip()
        package_dict[data.get("name")] = data
    fh.close()

# Load in plugins from this repo.
logger.info(f"Loading plugins from repo from {base_dir}, {os.getcwd()}")
for entry in entries:
    logger.debug(f"  * {entry}")

    plugin_file = os.path.join(base_dir, "integrations", entry, f"{entry}.py")
    if os.path.exists(plugin_file) is False:
        logger.warning(f"  !! {plugin_file} does not exists, slipping.")
        continue

    meta_file = os.path.join(base_dir, "integrations", entry, "meta.yml")
    if os.path.exists(meta_file) is True:
        with open(meta_file, 'r') as fh:
            data = yaml.safe_load(fh)
            name = data.get("name")
            data["summary"] = data.get("summary").strip()
            if name in package_dict:
                raise ValueError(f"Duplicate plugin name for {name}.")
            data.pop("type", None)
            package_dict[name] = data
            fh.close()

        with open(plugin_file, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
            finder = PluginValidator()
            finder.visit(tree)
            if len(finder.schema) == 0:
                logger.warning("  !! plugin does not have a schema section")
            data["schema"] = finder.schema
    else:
        logger.warning(f"  !! {meta_file} is missing, skipping.")

package = [v for k,v in package_dict.items()]
with open(os.path.join(base_dir, "catalog", "catalog.yml"), 'w') as fh:
    fh.write(yaml.dump(package, sort_keys=False))
    fh.close()
