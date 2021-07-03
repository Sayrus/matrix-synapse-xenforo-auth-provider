import requests


class XenforoApi:
    def __init__(self, api_key: str, endpoint: str):
        self.endpoint = endpoint
        self.auth_headers = {'xf-api-key': self.api_key}

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

