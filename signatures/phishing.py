"""
These are all of the signatures related to phishing
"""
from assemblyline_v4_service.common.utils import PASSWORD_WORDS
from jsjaws import PHISHING_INPUTS
from signatures.abstracts import ALL, ANY, Signature


class PhishingTerms(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="phishing_terms",
            description="JavaScript uses terms commonly associated with logging in",
            severity=1,
        )

    def process_output(self, output):
        results = []

        # First look for password prompts
        password_regex = f"\\b({'|'.join(PASSWORD_WORDS)})\\b"
        for line in output:
            results.extend(self.check_regex(password_regex, line.lower()))

        len_of_pwd_hits = len(results)

        if not len_of_pwd_hits:
            return

        # Next look for account prompts
        account_regex = f"\\b({'|'.join(PHISHING_INPUTS)})\\b"
        for line in output:
            results.extend(self.check_regex(account_regex, line.lower()))

        if len(results) <= len_of_pwd_hits:
            # Not phishing... we need both password and account prompts
            self.marks = []
        else:
            results_set = sorted(set(results))
            if len(results_set) > 25:
                self.marks.append(
                    f"The following terms were found in the document: {','.join(sorted(set(results_set))[:25])}. "
                    f"{len(results_set[25:])} marks were not displayed."
                )
            else:
                self.marks.append(f"The following terms were found in the document: {','.join(results_set)}")


class PhishingLogoDownload(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="phishing_logo_download",
            description="JavaScript reaches out to common URL that is used for hosting logos for organizations.",
            indicators=[
                "logo.clearbit.com",
                "vectorstock.com",
                "1.bp.blogspot.com",
                "2.bp.blogspot.com",
                "3.bp.blogspot.com",
                "4.bp.blogspot.com",
                "pngtoico.io",
                "aadcdn.msauth.net/shared/1.0/content/images/",
                "softwarereviews.s3.amazonaws.com/production/favicons/",
                "img.alicdn.com",
                "img.freepik.com",
                "splash247.com",
                "companieslogo.com",
                "upload.wikimedia.org",
            ],
            severity=1,
        )

    def process_output(self, output):
        indicator_list = [
            {"method": ANY, "indicators": self.indicators},
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)


class PhishingReEnterPrompt(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="phishing_reenter_prompt",
            description="JavaScript prompts user to re-enter account data.",
            indicators=["incorrect ", "wrong ", "try again", " be empty"],
            severity=0,
        )

    def process_output(self, output):
        indicator_list = [
            {"method": ANY, "indicators": self.indicators},
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)


class PhishingPostPassword(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="phishing_post_password",
            description="JavaScript makes network request via POST with password data.",
            severity=3,
        )

    def process_output(self, output):
        indicator_list = [
            {"method": ALL, "indicators": ["XMLHttpRequest"]},
            {"method": ANY, "indicators": ["JsJ@w$==C00l!", "JsJ%40w%24%3D%3DC00l!", "SnNKQHckPT1DMDBsIQ=="]},
        ]

        self.check_multiple_indicators_in_list(output, indicator_list)
