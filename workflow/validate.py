from workflow_base import WorkflowBase
from importlib import import_module
import subprocess
import os
import yaml
import ast
import sys
import tempfile
import json
from colorama import Fore, Style


class PluginValidator(ast.NodeVisitor):

    def __init__(self):
        super().__init__()

        self.schema = []
        self.has_schema_method = False
        self.has_change_password = False
        self.required_modules = []

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


class Validate(WorkflowBase):

    COVERAGE_PERC = 70.0

    def run(self, ref: str):

        entries = self.changed_integrations(ref)

        self.logger.debug(f"adding {self.base_dir} to python path")
        sys.path.insert(0, self.base_dir)

        # Load in plugins from this repo.
        for entry in entries:
            self.logger.debug(f"{Fore.CYAN}**********************************************************{Style.RESET_ALL}")
            self.logger.debug(f"{Fore.CYAN}* {entry}{Style.RESET_ALL}")
            self.logger.debug(f"{Fore.CYAN}**********************************************************{Style.RESET_ALL}")

            main_file = f"{entry}.py"

            init_file = os.path.join(self.base_dir, "integrations", entry, "__init__.py")
            if os.path.exists(init_file) is False:
                with open(init_file, "w") as fh:
                    fh.write("")
                    fh.close()

            plugin_file = os.path.join(self.base_dir, "integrations", entry, main_file)
            if os.path.exists(plugin_file) is False:
                raise ValueError(f"The python file '{entry}.py' file is missing for plugin {entry}")

            with open(plugin_file, "r", encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
                finder = PluginValidator()
                finder.visit(tree)
                if len(finder.schema) == 0:
                    raise ValueError(f"The python file '{main_file}' file is missing the config_schema method")

            meta_file = os.path.join(self.base_dir, "integrations", entry, "meta.yml")
            if os.path.exists(meta_file) is True:
                with open(meta_file, 'r') as fh:
                    data = yaml.safe_load(fh)
                    name = data.get("name")
                    author = data.get("author")
                    email = data.get("email")
                    summary = data.get("summary")
                    if name is None or name == "":
                        ValueError(f"!! the meta.yml file is missing the 'name' for {entry}")
                    if author is None or author == "":
                        ValueError(f"!! the meta.yml file is missing the 'author' for {entry}")
                    if email is None or email == "":
                        ValueError(f"!! the meta.yml file is missing the 'email' for {entry}")
                    if summary is None or summary == "":
                        ValueError(f"!! the meta.yml file is missing the 'summary' for {entry}")
                    fh.close()
            else:
                raise ValueError(f"The 'meta.yml' file is missing for plugin {entry}")

            with tempfile.TemporaryDirectory() as temp_dir:
                self.logger.info(f"temp directory is {temp_dir}")

                cmd = f"cd {temp_dir} && python3 -m venv test_venv"
                process = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)

                cmd = f"source {temp_dir}/test_venv/bin/activate && pip install -U pip"
                process = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                self.logger.debug(f"{Fore.WHITE}{process.stdout}{Style.RESET_ALL}")
                if process.stderr is not None and process.stderr != "":
                    self.logger.debug(f"{Fore.RED}{process.stderr}{Style.RESET_ALL}")

                cmd = f"source {temp_dir}/test_venv/bin/activate && pip install -r requirements.txt"
                process = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                self.logger.debug(f"{Fore.WHITE}{process.stdout}{Style.RESET_ALL}")
                if process.stderr is not None and process.stderr != "":
                    self.logger.debug(f"{Fore.RED}{process.stderr}{Style.RESET_ALL}")

                requirements_test_file = os.path.join(self.base_dir, "integrations", entry, "requirements_test.txt")
                if os.path.exists(requirements_test_file) is True:
                    cmd = f"source {temp_dir}/test_venv/bin/activate && pip install -r {requirements_test_file}"
                    process = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                    self.logger.debug(f"{Fore.WHITE}{process.stdout}{Style.RESET_ALL}")
                    if process.stderr is not None and process.stderr != "":
                        self.logger.debug(f"{Fore.RED}{process.stderr}{Style.RESET_ALL}")

                config_json_file = os.path.join(self.base_dir, "integrations", entry, "config.json")
                if os.path.exists(config_json_file) is True:
                    raise Exception("A config.json file detected in the plugin directory. Please remove this file.")

                try:
                    plugin_mod = import_module(f"integrations.{entry}.{entry}")
                    plugin_class = getattr(plugin_mod, "SaasPlugin")
                    mods = getattr(plugin_class, 'requirements')()

                    cmd = f"source {temp_dir}/test_venv/bin/activate && pip install {' '.join(mods)}"
                    process = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                    self.logger.debug(f"{Fore.WHITE}{process.stdout}{Style.RESET_ALL}")
                    if process.stderr is not None and process.stderr != "":
                        self.logger.debug(f"{Fore.RED}{process.stderr}{Style.RESET_ALL}")

                except Exception as err:
                    self.logger.error(str(err))
                    self.logger.info(sys.path)

                cmd = f"source {temp_dir}/test_venv/bin/activate "\
                      f"&& cd {os.path.join(self.base_dir, 'integrations', entry)} "\
                      f"&& coverage run --rcfile={os.path.join(self.base_dir, 'coveragerc')} -m pytest "\
                      f"&& coverage report -m --rcfile={os.path.join(self.base_dir, 'coveragerc')} "\
                      f"&& coverage json --rcfile={os.path.join(self.base_dir, 'coveragerc')}"
                process = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                if "FAILURES" in process.stdout:
                    self.logger.debug(f"{Fore.RED}{process.stdout}{Style.RESET_ALL}")
                    raise Exception("Unit test failed.")
                else:
                    self.logger.debug(f"{Fore.GREEN}{process.stdout}{Style.RESET_ALL}")
                if process.stderr is not None and process.stderr != "":
                    self.logger.debug(f"{Fore.RED}{process.stderr}{Style.RESET_ALL}")

                coverage_file = os.path.join(self.base_dir, "integrations", entry, "coverage.json")
                if os.path.exists(coverage_file) is False:
                    raise Exception("No coverage file found")

                with open(coverage_file, "r") as fh:
                    coverage = json.load(fh)
                    info = coverage["files"].get(main_file)
                    if info is None:
                        raise Exception(f"Could not find {main_file} in coverage JSON.")
                    percentage = info["summary"].get("percent_covered")
                    self.logger.info(f"code coverage of {main_file} is {percentage} percent")
                    if percentage < Validate.COVERAGE_PERC:
                        raise Exception(f"Coverage is too low. Require {Validate.COVERAGE_PERC} percent coverage.")

            self.logger.info("plugin is valid\n")


if __name__ == "__main__":
    validate = Validate()
    validate.run(ref=sys.argv[1])
