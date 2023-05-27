"""
This plugin searches for GitHub tokens
"""
import re
import requests
from typing import Generator
from detect_secrets.constants import VerifiedResult

from detect_secrets.plugins.base import RegexBasedDetector


class GitHubTokenDetector(RegexBasedDetector):
    """Scans for GitHub tokens."""
    secret_type = 'GitHub Token'

    denylist = [
        # ref. https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
        re.compile(r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}'),
    ]

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        for regex in self.denylist:
            match = regex.search(string)
            if match:
                yield match.group(0)

    def verify(self,secret: str) -> VerifiedResult:
        headers = {"Authorization": f"Bearer {secret}"}
        url = "https://api.github.com/user"
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            return VerifiedResult.VERIFIED_TRUE
        return VerifiedResult.VERIFIED_FALSE