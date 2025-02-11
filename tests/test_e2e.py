import asyncio
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
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
                        "public_attribute_search_path": "profile.user_settings.public",
                        "whitelist_requester_id_patterns": [
                            "@whitelisted:my.domain.name"
                        ],
                    },
                }
            ]
            config["rc_login"] = {
                "address": {"per_second": 9999, "burst_count": 9999},
            }

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
            def read_output(pipe: Union[IO[str], None]) -> None:
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

    async def get_public_attribute_of_user(
        self, user_id: str, access_token: str
    ) -> Union[bool, None]:
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
        is_public = user_settings.get("public", None)
        if is_public is None:
            return None
        if isinstance(is_public, str):
            is_public = is_public.lower() == "true"
        return is_public

    async def set_public_attribute_of_user(
        self, user_id: str, public_attribute: bool, access_token: str
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
        update_json["user_settings"]["public"] = public_attribute
        response = requests.put(
            f"http://localhost:8008/_matrix/client/v3/user/{user_id}/account_data/profile",
            json=update_json,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(response.status_code, 200)
        user_public_attribute = await self.get_public_attribute_of_user(
            user_id, access_token
        )
        self.assertEqual(user_public_attribute, public_attribute)

    def assert_mounted_module(self) -> None:
        version_cmd = [
            sys.executable,
            "-m",
            "synapse_limit_user_directory",
            "--version",
        ]
        subprocess.check_call(version_cmd)

    async def test_limit_user_directory(self) -> None:
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
            for i in range(6):
                await self.register_user(
                    config_path, synapse_dir, f"user{i}", f"password{i}", False
                )
                (username, access_token) = await self.login_user(
                    f"user{i}", f"password{i}"
                )
                creds.append((username, access_token))

            for i in range(6):
                if i == 0 or i == 1:
                    # User 0, 1: private
                    await self.set_public_attribute_of_user(
                        creds[i][0], False, creds[i][1]
                    )
                elif i == 2 or i == 3:
                    # User 2, 3: public
                    await self.set_public_attribute_of_user(
                        creds[i][0], True, creds[i][1]
                    )
                elif i == 4 or i == 5:
                    # User 4, 5: not set
                    ...

            for i in range(6):
                # all users should only see public users
                (username, access_token) = creds[i]
                users = await self.search_users("user", access_token)
                for user in users:
                    other_user_index = int(user[5])  # @user0, @user1, @user2, ...
                    self.assertIn(other_user_index, [2, 3])

                    user_is_public = await self.get_public_attribute_of_user(
                        user, creds[other_user_index][1]
                    )
                    self.assertEqual(user_is_public, True)

            # Register whitelisted user
            await self.register_user(
                config_path, synapse_dir, "whitelisted", "password", True
            )
            (whitelisted_username, whitelisted_access_token) = await self.login_user(
                "whitelisted", "password"
            )
            users = await self.search_users("user", whitelisted_access_token)
            self.assertEqual(len(users), 6)

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
