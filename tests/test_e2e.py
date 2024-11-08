import asyncio
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from time import perf_counter
from typing import IO, Literal, Tuple, Union
from uuid import uuid4

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
                {"module": "synapse_room_code.SynapseRoomCode", "config": {}}
            ]

            config["database"] = {
                "name": "sqlite3",
                "args": {"database": "homeserver.db"},
            }
            config["user_directory"] = {
                "enabled": "true",
                "search_all_users": "true",
                "prefer_local_users": "true",
                "show_locked_users": "true",
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

    async def create_private_room(self, access_token: str):
        headers = {"Authorization": f"Bearer {access_token}"}
        # Create a room with user 1
        create_room_url = "http://localhost:8008/_matrix/client/v3/createRoom"
        create_room_data = {"visibility": "private", "preset": "private_chat"}
        response = requests.post(
            create_room_url,
            json=create_room_data,
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        room_id = response.json()["room_id"]
        self.assertIsInstance(room_id, str)
        return room_id

    async def set_room_knockable_with_code(
        self,
        room_id: str,
        access_token: str,
        access_code: Union[str, None] = None,
    ):
        headers = {"Authorization": f"Bearer {access_token}"}
        set_join_rules_url = f"http://localhost:8008/_matrix/client/v3/rooms/{room_id}/state/m.room.join_rules"
        state_event_content = {
            JOIN_RULE_CONTENT_KEY: KNOCK_JOIN_RULE_VALUE,
            ACCESS_CODE_JOIN_RULE_CONTENT_KEY: access_code,
        }
        response = requests.put(
            set_join_rules_url,
            json=state_event_content,
            headers=headers,
        )
        self.assertEqual(response.status_code, 200)
        event_id = response.json()["event_id"]
        self.assertIsInstance(event_id, str)
        return event_id

    async def register_user(
        self, config_path: str, dir: str, user: str, password: str, admin: bool
    ):
        register_user_cmd = [
            "register_new_matrix_user",
            f"-c={config_path}",
            f"--user={user}",
            f"--password={password}",
        ]
        if admin:
            register_user_cmd.append("--admin")
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
