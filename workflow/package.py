#!python

from plugin_dev.test_base import WorkflowBase, PluginVisitor
import os
import yaml
import json
import ast
import sys
import hmac
import hashlib


class Package(WorkflowBase):

    @staticmethod
    def make_script_signature(plugin_code_bytes: bytes) -> str:

        # To use HMAC, we need to have a key; the key is not a secret, we just want to make a unique digest.
        this_is_not_a_secret = b"NOT_IMPORTANT"
        return hmac.new(this_is_not_a_secret, plugin_code_bytes, hashlib.sha256).hexdigest()

    def run(self):

        entries = os.listdir(os.path.join(self.base_dir, "integrations"))

        sys.path.append(self.base_dir)
        self.logger.debug(f"Path = {sys.path}")

        package_dict = {}

        # Load in the builtin SaaS plugins from KDNRM
        self.logger.info("Loading built in plugins.")
        with open(os.path.join(self.base_dir, "workflow", "builtin.yml"), 'r') as fh:
            datas = yaml.safe_load_all(fh)
            for data in datas:
                if data.get("summary") is not None:
                    data["summary"] = data.get("summary").strip()
                package_dict[data.get("name")] = data
            fh.close()

        # Load in plugins from this repo.
        self.logger.info(f"Loading plugins from repo from {self.base_dir}, {os.getcwd()}")
        for entry in entries:
            if entry.startswith("__") is True or entry.endswith(".py") is True:
                continue
            self.logger.debug(f"  * {entry}")

            plugin_file = os.path.join(self.base_dir, "integrations", entry, f"{entry}.py")
            if not os.path.exists(plugin_file):
                self.logger.warning(f"  !! {plugin_file} does not exists, skipping.")
                continue

            data = {}

            with open(plugin_file, "rb") as fh:
                plugin_code_bytes = fh.read()

                tree = ast.parse(plugin_code_bytes.decode("utf-8"))
                info = PluginVisitor()
                info.visit(tree)

                sig = self.make_script_signature(plugin_code_bytes=plugin_code_bytes)

                data["name"] = info.name
                data["type"] = "catalog"
                data["author"] = info.author
                data["email"] = info.email
                data["summary"] = info.summary
                data["file"] = "https://raw.githubusercontent.com/Keeper-Security"\
                               f"/discovery-and-rotation-saas-dev/refs/heads/main/integrations"\
                               f"/{entry}/{entry}.py"
                data["file_sig"] = sig
                data["fields"] = info.schema
                data["readme"] = None
                data["allows_remote_management"] = False
                if info.readme is not None:
                    url = "https://github.com/Keeper-Security" \
                          "/discovery-and-rotation-saas-dev/blob/main/integrations/" \
                          f"{entry}/{info.readme}"
                    data["readme"] = url
                package_dict[info.name] = data

        self.logger.info("Saving catalog.json")

        p = [v for k, v in package_dict.items()]
        with open(os.path.join(self.base_dir, "catalog.json"), 'w') as fh:
            fh.write(json.dumps(p, sort_keys=False, indent=4))
            fh.close()


if __name__ == "__main__":
    package = Package()
    package.run()
