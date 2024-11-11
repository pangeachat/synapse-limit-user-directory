import logging
import re
from datetime import date, datetime
from typing import Any, Dict, List

import attr
from synapse.module_api import ModuleApi, UserProfile


@attr.s(auto_attribs=True, frozen=True)
class SynapseLimitUserDirectoryConfig:
    dob_search_path: str
    filter_if_missing_dob: bool
    dob_strptime_formats: List[str]


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
        # verify it's dot-syntax (i.e. foo.bar.foobar)
        if re.match(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$", dob_search_path) is None:
            raise ValueError(
                'Config "dob_search_path" must be in dot-syntax (i.e. profile.user_settings.date_of_birth)'
            )

        filter_if_missing_dob = config.get("filter_if_missing_dob", True)
        if filter_if_missing_dob is None:
            filter_if_missing_dob = False

        dob_strptime_formats = config.get("dob_strptime_format")
        if dob_strptime_formats is None:
            dob_strptime_formats = [
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d",
            ]

        return SynapseLimitUserDirectoryConfig(
            dob_search_path=dob_search_path,
            filter_if_missing_dob=filter_if_missing_dob,
            dob_strptime_formats=dob_strptime_formats,
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
            global_data = global_data.get(path, None)
            if global_data is None:
                return self._config.filter_if_missing_dob
        if not isinstance(global_data, str):
            return self._config.filter_if_missing_dob

        dob_str = global_data

        dob = None
        for fmt in self._config.dob_strptime_formats:
            try:
                dob = datetime.strptime(dob_str, fmt)
            except ValueError:
                pass
        if dob is None:
            raise ValueError(
                f"Date '{dob_str}' does not match any known formats: {', '.join(self._config.dob_strptime_formats)}."
            )

        # If today is past the threshold then the user is over 18 and OK to
        # return, which is equivalent to returning False.
        return datetime.today() <= dob.replace(year=dob.year + 18)
