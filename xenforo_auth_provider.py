import os
import requests


class XenforoAuthProvider(object):
    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        self.endpoint = config.endpoint

        self.api_key = config.api_key or os.getenv('XF_API_KEY')
        if not self.api_key:
            raise RuntimeError('Missing API Key')

    def get_supported_login_types(self):
        return {'m.login.password': ('password',)}

    async def check_3pid_auth(self, medium, address, password):
        if medium != "email":
            return None

        payload = {'login': address, 'password': password}
        headers = {'xf-api-key': self.api_key}
        r = requests.post(self.endpoint + "/api/auth", data=payload, headers=headers)
        if r.status_code != 200:
            return False
        r = r.json()
        if r["success"] is not True:
            return False

        user_id = self.account_handler.get_qualified_user_id(r['user']['user_id'])
        display_name = r['user']['username']
        if await self.account_handler.check_user_exists(user_id):
            return user_id
        user_id, access_token = await self.account_handler.register(localpart=user_id, displayname=display_name)
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
