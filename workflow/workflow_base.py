from __future__ import annotations
import logging
import os
import subprocess
from colorama import Fore, Style
from typing import List


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







