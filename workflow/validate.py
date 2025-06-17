from plugin_dev.test_base import WorkflowBase, PluginVisitor
from importlib import import_module
import subprocess
import os
import ast
import sys
import tempfile
import json
from colorama import Fore, Style


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
            if not os.path.exists(init_file):
                with open(init_file, "w") as fh:
                    fh.write("")
                    fh.close()

            plugin_file = os.path.join(self.base_dir, "integrations", entry, main_file)
            if not os.path.exists(plugin_file):
                raise ValueError(f"The python file '{entry}.py' file is missing for plugin {entry}")

            with open(plugin_file, "r", encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
                validation = PluginVisitor()
                validation.visit(tree)

                if validation.name is None or validation.name == "":
                    raise ValueError(f"The python file '{main_file}' file is blank the 'name' class attribute.")
                if validation.summary is None or validation.summary == "":
                    raise ValueError(f"The python file '{main_file}' file is blank the 'summary' class attribute.")
                if validation.readme is None or validation.readme == "":
                    raise ValueError(f"The python file '{main_file}' file is blank the 'readme' class attribute.")
                if validation.author is None or validation.author == "":
                    raise ValueError(f"The python file '{main_file}' file is blank the 'author' class attribute.")
                if validation.email is None or validation.email == "":
                    raise ValueError(f"The python file '{main_file}' file is blank the 'email' class attribute.")
                if len(validation.schema) == 0:
                    raise ValueError(f"The python file '{main_file}' file is missing the config_schema method")

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
                if os.path.exists(requirements_test_file):
                    cmd = f"source {temp_dir}/test_venv/bin/activate && pip install -r {requirements_test_file}"
                    process = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
                    self.logger.debug(f"{Fore.WHITE}{process.stdout}{Style.RESET_ALL}")
                    if process.stderr is not None and process.stderr != "":
                        self.logger.debug(f"{Fore.RED}{process.stderr}{Style.RESET_ALL}")

                config_json_file = os.path.join(self.base_dir, "integrations", entry, "config.json")
                if os.path.exists(config_json_file):
                    raise Exception("A config.json file detected in the plugin directory. Please remove this file.")

                try:
                    packages = validation.requirements
                    if len(packages) > 0:
                        cmd = f"source {temp_dir}/test_venv/bin/activate && pip install {' '.join(packages)}"
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
                if not os.path.exists(coverage_file):
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
    ref = "main"
    if len(sys.argv) > 1:
        ref = sys.argv[1]

    try:
        validate.run(ref=ref)
    except Exception as err:
        print(f"{Fore.RED}TEST FAIL: {err}{Style.RESET_ALL}")
        sys.exit(1)
