from datetime import date, datetime
import logging
import re
from typing import Any, Dict

import attr
from synapse.module_api import ModuleApi, UserProfile


@attr.s(auto_attribs=True, frozen=True)
class SynapseLimitUserDirectoryConfig:
    dob_search_path: str
    filter_if_missing_dob: bool = False
    dob_strptime_format: str = "%Y-%m-%dT%H:%M:%S.%f"


logger = logging.getLogger("synapse.modules.synapse_limit_user_directory")


class SynapseLimitUserDirectory:
    def __init__(self, config: SynapseLimitUserDirectoryConfig, api: ModuleApi):
        self._api = api
        self._config = config

        self._api.register_spam_checker_callbacks(
            check_username_for_spam=self.check_username_for_spam,
        )

    @staticmethod
    def parse_config(config: Dict[str, Any]) -> SynapseLimitUserDirectoryConfig:
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary.")
        dob_search_path = config.get("dob_search_path")
        if not isinstance(dob_search_path, str):
            raise ValueError('Config "dob_search_path" must be a string')
        # verify it's dot-syntax (i.e. foo.bar.foobar) and must starts with "global_data."
        if not dob_search_path.startswith("global_data."):
            raise ValueError('Config "dob_search_path" must start with "global_data."')
        if re.match(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$", dob_search_path) is None:
            raise ValueError(
                'Config "dob_search_path" must be in dot-syntax (i.e. global_data.profile.user_settings.date_of_birth)'
            )

        filter_if_missing_dob = config.get("filter_if_missing_dob", True)
        dob_strptime_format = config.get("dob_strptime_format")

        return SynapseLimitUserDirectoryConfig(
            dob_search_path=dob_search_path,
            filter_if_missing_dob=filter_if_missing_dob,
            dob_strptime_format=dob_strptime_format,
        )

    async def check_username_for_spam(self, user_profile: UserProfile) -> bool:
        """
        Decide whether to filter a user from the user directory results.

        # Return true to *exclude* the user from the results.
        """
        user_id = user_profile["user_id"]

        # For remote users, nothing to do.
        if not self._api.is_mine(user_id):
            return False

        # For local users, check if they're 18+ based on their account data.
        dob_search_paths = self._config.dob_search_path.split(".")
        global_data = await self._api.account_data_manager.get_global(
            user_id, dob_search_paths[0]
        )
        if global_data is None:
            return self._config.filter_if_missing_dob
        for path in dob_search_paths[1:]:
            dob_str = global_data.get(path, None)
            if dob_str is None:
                return self._config.filter_if_missing_dob
        if not isinstance(dob_str, str):
            return self._config.filter_if_missing_dob
        try:
            # Attempt to parse the date string using the user-defined format
            dob = datetime.strptime(dob_str, self._config.dob_strptime_format)
        except ValueError:
            # Raise a custom error if parsing fails
            raise ValueError(
                f"The date string '{dob_str}' does not match the format '{self._config.dob_strptime_format}'."
            )

        # If today is past the threshold then the user is 18+ and OK to return,
        # which is equivalent to returning False.
        return date.today() < dob.replace(year=dob.year + 18)
