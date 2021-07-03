import os

from xenforo_api import XenforoApi


class XenforoAuthProvider(object):
    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        api_key = config.api_key or os.getenv('XF_API_KEY')
        if not api_key:
            raise RuntimeError('Missing API Key')
        self.api = XenforoApi(api_key, config.endpoint)

    def get_supported_login_types(self):
        return {'m.login.password': ('password',)}

    async def check_auth(self, username, login_type, login_dict):
        password = login_dict['password']
        if not password:
            return False

        # XenForo login only
        if not (username.startswith("@xf-") and ":" in username):
            return False

        # We need to fetch the mail from xf-id
        uid = username.split(":", 1)[0][4:]
        if not uid.isdigit():
            return False
        r = self.api.get_user_from_uid(uid)
        username = r['user']['username']

        r = self.api.post_auth(username, password)
        if r is False:
            return False

        # Prefix with xf as numeric IDs are reserved for guests
        localpart = "xf-" + str(r['user']['user_id'])
        user_id = self.account_handler.get_qualified_user_id(localpart)
        display_name = r['user']['username']

        if not await self.account_handler.check_user_exists(user_id):
            user_id, access_token = await self.account_handler.register(localpart=localpart, displayname=display_name)
        self.account_handler.set_profile_avatar_url(localpart, r['user']['avatar_urls'])
        return user_id

    async def check_3pid_auth(self, medium, address, password):
        if medium != "email":
            return None

        r = self.api.post_auth(address, password)
        if r is False:
            return False

        # Prefix with xf as numeric IDs are reserved for guests
        localpart = "xf-" + str(r['user']['user_id'])
        user_id = self.account_handler.get_qualified_user_id(localpart)
        display_name = r['user']['username']
        if not await self.account_handler.check_user_exists(user_id):
            user_id, access_token = await self.account_handler.register(localpart=localpart, displayname=display_name)
        self.account_handler.set_profile_avatar_url(localpart, r['user']['avatar_urls'])
        return user_id

    @staticmethod
    def parse_config(config):
        class _XenforoConfig(object):
            endpoint = ''
            api_key = ''

        xf_config = _XenforoConfig()

        if not config['endpoint']:
            raise Exception("Missing endpoint config")

        xf_config.endpoint = config["endpoint"]
        try:
            xf_config.api_key = config["api_key"]
        except (TypeError, KeyError):
            pass
        return xf_config
