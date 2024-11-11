import asyncio
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime
from typing import IO, List, Tuple, Union

import aiounittest
import requests
import yaml

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,  # Set the logging level
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",  # Log format
    filename="synapse.log",  # File to log to
    filemode="w",  # Append mode (use 'w' to overwrite each time)
)


class TestE2E(aiounittest.AsyncTestCase):
    async def start_test_synapse(
        self,
        postgresql_url: Union[str, None] = None,
    ) -> Tuple[str, str, subprocess.Popen, threading.Thread, threading.Thread]:
        try:
            synapse_dir = tempfile.mkdtemp()

            # Generate Synapse config with server name 'my.domain.name'
            config_path = os.path.join(synapse_dir, "homeserver.yaml")
            generate_config_cmd = [
                sys.executable,
                "-m",
                "synapse.app.homeserver",
                "--server-name=my.domain.name",
                f"--config-path={config_path}",
                "--report-stats=no",
                "--generate-config",
            ]
            subprocess.check_call(generate_config_cmd)

            # Modify the config to include the module
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            log_config_path = config.get("log_config")
            config["modules"] = [
                {
                    "module": "synapse_limit_user_directory.SynapseLimitUserDirectory",
                    "config": {
                        "dob_search_path": "profile.user_settings.date_of_birth",
                    },
                }
            ]

            config["database"] = {
                "name": "sqlite3",
                "args": {"database": "homeserver.db"},
            }
            config["user_directory"] = {
                "enabled": True,
                "search_all_users": True,
                "prefer_local_users": True,
                "show_locked_users": True,
            }
            with open(config_path, "w") as f:
                yaml.dump(config, f)

            # Modify log config to log to console
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            with open(log_config_path, "r") as f:
                log_config = yaml.safe_load(f)
            log_config["root"]["handlers"] = ["console"]
            log_config["root"]["level"] = "DEBUG"
            with open(log_config_path, "w") as f:
                yaml.dump(log_config, f)

            # Run the Synapse server
            run_server_cmd = [
                sys.executable,
                "-m",
                "synapse.app.homeserver",
                "--config-path",
                config_path,
            ]
            server_process = subprocess.Popen(
                run_server_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=synapse_dir,
                text=True,
            )

            # Start threads to read stdout and stderr concurrently
            def read_output(pipe: Union[IO[str], None]):
                if pipe is None:
                    return
                for line in iter(pipe.readline, ""):
                    logger.debug(line)
                pipe.close()

            stdout_thread = threading.Thread(
                target=read_output, args=(server_process.stdout,)
            )
            stderr_thread = threading.Thread(
                target=read_output, args=(server_process.stderr,)
            )
            stdout_thread.start()
            stderr_thread.start()

            # Wait for the server to start by polling the root URL
            server_url = "http://localhost:8008"
            max_wait_time = 10  # Maximum wait time in seconds
            wait_interval = 1  # Interval between checks in seconds
            total_wait_time = 0
            server_ready = False
            while server_ready is False and total_wait_time < max_wait_time:
                try:
                    response = requests.get(server_url)
                    if response.status_code == 200:
                        server_ready = True
                        break
                except requests.exceptions.ConnectionError:
                    print(
                        f"Synapse server not yet up, retrying {total_wait_time}/{max_wait_time}..."
                    )
                finally:
                    await asyncio.sleep(wait_interval)
                    total_wait_time += wait_interval

            if server_ready is False:
                self.fail("Synapse server did not start successfully")
            else:
                print("Synapse server started successfully")

            return (
                synapse_dir,
                config_path,
                server_process,
                stdout_thread,
                stderr_thread,
            )
        except Exception as e:
            server_process.terminate()
            server_process.wait()
            stdout_thread.join()
            stderr_thread.join()
            shutil.rmtree(synapse_dir)

            raise e

    async def register_user(
        self, config_path: str, dir: str, user: str, password: str, admin: bool
    ) -> None:
        register_user_cmd = [
            "register_new_matrix_user",
            f"-c={config_path}",
            f"--user={user}",
            f"--password={password}",
        ]
        if admin:
            register_user_cmd.append("--admin")
        else:
            register_user_cmd.append("--no-admin")
        subprocess.check_call(register_user_cmd, cwd=dir)

    async def login_user(self, user: str, password: str) -> Tuple[str, str]:
        login_url = "http://localhost:8008/_matrix/client/v3/login"
        login_data = {
            "type": "m.login.password",
            "user": user,
            "password": password,
        }
        response = requests.post(login_url, json=login_data)
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        access_token = response_json["access_token"]
        user_id = response_json["user_id"]
        self.assertIsInstance(access_token, str)
        self.assertIsInstance(user_id, str)
        return (user_id, access_token)

    async def search_users(self, search_term: str, access_token: str) -> List[str]:
        response = requests.post(
            "http://localhost:8008/_matrix/client/v3/user_directory/search",
            json={"limit": 100, "search_term": search_term},
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        self.assertIsInstance(response_json, dict)
        results = response_json.get("results")
        self.assertIsInstance(results, list)
        users: List[str] = []
        for result in results:
            user_id = result.get("user_id")
            self.assertIsInstance(user_id, str)
            users.append(user_id)
        return users

    async def get_dob_of_user(self, user_id: str, access_token: str) -> datetime | None:
        response = requests.get(
            f"http://localhost:8008/_matrix/client/v3/user/{user_id}/account_data/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code == 404:
            return None
        response_json = response.json()
        self.assertIsInstance(response_json, dict)
        user_settings = response_json.get("user_settings", {})
        self.assertIsInstance(user_settings, dict)
        dob_str = user_settings.get("date_of_birth", None)
        if dob_str is None:
            return None
        dob = datetime.strptime(dob_str, "%Y-%m-%dT%H:%M:%S")
        return dob

    async def set_dob_of_user(
        self, user_id: str, dob: datetime, access_token: str
    ) -> None:
        response = requests.get(
            f"http://localhost:8008/_matrix/client/v3/user/{user_id}/account_data/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code == 404:
            response_json = {}
        else:
            response_json = response.json()
            if not isinstance(response_json, dict):
                self.fail(f"Response JSON is not a dictionary: {response_json}")

        update_json = response_json.copy()
        if "user_settings" not in update_json:
            update_json["user_settings"] = {}
        update_json["user_settings"]["date_of_birth"] = dob.strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        response = requests.put(
            f"http://localhost:8008/_matrix/client/v3/user/{user_id}/account_data/profile",
            json=update_json,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(response.status_code, 200)
        dob = await self.get_dob_of_user(user_id, access_token)
        self.assertEqual(
            dob,
            datetime.strptime(
                update_json["user_settings"]["date_of_birth"], "%Y-%m-%dT%H:%M:%S"
            ),
        )

    def assert_mounted_module(self) -> None:
        version_cmd = [
            sys.executable,
            "-m",
            "synapse_limit_user_directory",
            "--version",
        ]
        subprocess.check_call(version_cmd)

    async def test_limit_user_directory(self):
        synapse_dir = None
        server_process = None
        stdout_thread = None
        stderr_thread = None
        try:
            (
                synapse_dir,
                config_path,
                server_process,
                stdout_thread,
                stderr_thread,
            ) = await self.start_test_synapse()

            self.assert_mounted_module()

            creds: List[Tuple[str, str]] = []
            for i in range(5):
                await self.register_user(
                    config_path, synapse_dir, f"user{i}", f"password{i}", False
                )
                (username, access_token) = await self.login_user(
                    f"user{i}", f"password{i}"
                )
                creds.append((username, access_token))

            now = datetime.now()
            under_eighteen = now.replace(year=now.year - 17, microsecond=0)
            over_eighteen = now.replace(year=now.year - 19, microsecond=0)
            for i in range(5):
                if i % 2 == 0:
                    await self.set_dob_of_user(creds[i][0], under_eighteen, creds[i][1])
                else:
                    await self.set_dob_of_user(creds[i][0], over_eighteen, creds[i][1])

            for i in range(5):
                (username, access_token) = creds[i]
                users = await self.search_users("user", access_token)
                for user in users:
                    user_index = int(user[5])  # @user0, @user1, @user2, ...
                    dob = await self.get_dob_of_user(user, creds[user_index][1])
                    self.assertEqual(dob, over_eighteen)

            # Clean up
            if server_process is not None:
                server_process.terminate()
                server_process.wait()
            if stdout_thread is not None:
                stdout_thread.join()
            if stderr_thread is not None:
                stderr_thread.join()
            if synapse_dir is not None:
                shutil.rmtree(synapse_dir)
        except Exception as e:
            if server_process is not None:
                server_process.terminate()
                server_process.wait()
            if stdout_thread is not None:
                stdout_thread.join()
            if stderr_thread is not None:
                stderr_thread.join()
            if synapse_dir is not None:
                shutil.rmtree(synapse_dir)
            raise e
