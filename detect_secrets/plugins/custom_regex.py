import re
from ..settings import get_settings
from .base import RegexBasedDetector
from ..constants import VerifiedResult


class CustomRegex(RegexBasedDetector):
    """Scans for Basic Auth formatted URIs."""
    secret_type = 'Custom_Regex'
    patterns = get_settings().custom_regex
    def denylist(self) :
        deny = {}
        for pattern in self.patterns:
            try:
                deny[self.patterns[pattern]] = re.compile(self.patterns[pattern])
            except:
                print(pattern,self.patterns[pattern])
        return deny

    def analyze_string(self, string: str):
        deny = self.denylist()
        for regex in deny:
            self.secret_type = self.patterns.inverse[regex]
            # print(string)
            for match in deny[regex].findall(string): 
                if isinstance(match, tuple):
                    for submatch in filter(bool, match):
                        # It might make sense to paste break after yielding
                        yield submatch
                else:
                    yield match
    
    def verify(self,secret: str) -> VerifiedResult:
        '''
        Calls matching verification function from config if present
        '''
        verifications = get_settings().verify
        if self.secret_type in verifications.keys():
            if verifications[self.secret_type](secret):
                return VerifiedResult.VERIFIED_TRUE
            return VerifiedResult.VERIFIED_FALSE
        return VerifiedResult.UNVERIFIED