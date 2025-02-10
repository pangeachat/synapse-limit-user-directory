import logging
import re
from typing import Any, Dict

import attr
from synapse.module_api import ModuleApi, UserProfile


@attr.s(auto_attribs=True, frozen=True)
class SynapseLimitUserDirectoryConfig:
    public_attribute_search_path: str
    whitelist_requester_id_patterns: list[str]


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
        public_attribute_search_path = config.get("public_attribute_search_path")
        if not isinstance(public_attribute_search_path, str):
            raise ValueError('Config "dob_search_path" must be a string')
        # verify it's dot-syntax (i.e. foo.bar.foobar)
        if (
            re.match(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$", public_attribute_search_path)
            is None
        ):
            raise ValueError(
                'Config "public_attribute_search_path" must be in dot-syntax (i.e. profile.user_settings.public)'
            )

        # whitelist_requester_id_patterns is a list of regex patterns to match against the requester ID. If a pattern matches, the user will be included in the results if what is searched for matches their username.
        whitelist_requester_id_patterns = config.get(
            "whitelist_requester_id_patterns", []
        )
        if not isinstance(whitelist_requester_id_patterns, list):
            raise ValueError('Config "whitelist_requester_id_patterns" must be a list')
        for pattern in whitelist_requester_id_patterns:
            if not isinstance(pattern, str):
                raise ValueError(
                    'Config "whitelist_requester_id_patterns" must be a list of strings'
                )

        return SynapseLimitUserDirectoryConfig(
            public_attribute_search_path=public_attribute_search_path,
            whitelist_requester_id_patterns=whitelist_requester_id_patterns,
        )

    async def check_username_for_spam(
        self, user_profile: UserProfile, requester_id: str
    ) -> bool:
        """
        Decide whether to filter a user from the user directory results.

        :param user_profile: The user profile to check.
        :param requester_id: The user ID of the requester, in @<username>:<server> format.

        # Return true to *exclude* the user from the results.
        """
        # Bypass the filter if the username matches the whitelist pattern.
        for pattern in self._config.whitelist_requester_id_patterns:
            print(f"Checking {requester_id} against {pattern}")
            if re.match(pattern, requester_id):
                print(f"Matched {requester_id} against {pattern}")
                return False

        user_id = user_profile["user_id"]

        # For remote users, nothing to do.
        if not self._api.is_mine(user_id):
            return False

        # For local users, check if the user has their profile set to public
        public_attribute_search_path = self._config.public_attribute_search_path.split(
            "."
        )
        # If the user does not set their profile to public, we default them to
        # be private, which is equivalent to returning True to indicate this
        # username should be filtered.
        global_data = await self._api.account_data_manager.get_global(
            user_id, public_attribute_search_path[0]
        )
        if global_data is None:
            return True
        for path in public_attribute_search_path[1:]:
            global_data = global_data.get(path, None)
            if global_data is None:
                return True
        if not isinstance(global_data, str):
            return True

        is_public = global_data.lower() == "true"

        return not is_public
