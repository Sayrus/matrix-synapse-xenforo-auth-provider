import os
import requests


class XenforoApi:
    def __init__(self, api_key: str, endpoint: str):
        self.endpoint = endpoint
        self.auth_headers = {'xf-api-key': api_key}

    def post_auth(self, login: str, password: str):
        payload = {'login': login, 'password': password}
        r = requests.post(self.endpoint + "/api/auth", data=payload, headers=self.auth_headers)
        if r.status_code != 200:
            return False
        r = r.json()
        if r["success"] is not True:
            return False
        return r

    def get_user_from_uid(self, uid: str):
        if not uid.isdigit():
            raise ValueError("UID must represent an integer")

        r = requests.get(self.endpoint + '/api/users/' + uid, headers=self.auth_headers)
        if r.status_code != 200:
            return False
        return r.json()


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
        self.sync_user_profile(localpart, r)
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

        self.sync_user_profile(localpart, r)
        return user_id

    def sync_user_profile(self, localpart, r):
        store = self.account_handler._hs.get_profile_handler().store
        # Ideally, there is a better way for these as we access a protected member
        store.set_profile_displayname(localpart, r['user']['username'])
        store.set_profile_avatar_url(localpart, r['user']['avatar_urls']['o'])

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
