#!python

from plugin_dev.test_base import WorkflowBase, PluginVisitor
import os
import yaml
import json
import ast
import sys


class Package(WorkflowBase):

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
                print(data)
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
            if os.path.exists(plugin_file) is False:
                self.logger.warning(f"  !! {plugin_file} does not exists, slipping.")
                continue

            data = {}

            with open(plugin_file, "r", encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
                info = PluginVisitor()
                info.visit(tree)

                data["name"] = info.name
                data["type"] = "catalog"
                data["author"] = info.author
                data["email"] = info.email
                data["summary"] = info.summary
                data["file"] = "https://raw.githubusercontent.com/Keeper-Security"\
                               f"/discovery-and-rotation-saas-dev/refs/heads/main/integrations"\
                               f"/{entry}/{entry}.py"
                data["schema"] = info.schema
                data["readme"] = None
                if info.readme is not None:
                    url = "https://github.com/Keeper-Security" \
                          "/discovery-and-rotation-saas-dev/blob/main/integrations/" \
                          f"{entry}/{info.readme}"
                    data["readme"] = url
                package_dict[info.name] = data

        self.logger.info("Saving catalog.json")

        package = [v for k,v in package_dict.items()]
        with open(os.path.join(self.base_dir, "catalog.json"), 'w') as fh:
            fh.write(json.dumps(package, sort_keys=False, indent=4))
            fh.close()


if __name__ == "__main__":
    package = Package()
    package.run()
