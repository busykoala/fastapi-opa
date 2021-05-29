from dataclasses import dataclass
from pathlib import Path
from typing import Dict
from typing import Union

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import SAMLException


@dataclass
class SAMLConfig:
    settings_directory: str


class SAMLAuthentication(AuthInterface):
    def __init__(self, config: SAMLConfig):
        self.config = config
        self.custom_folder = Path(self.config.settings_directory)

    async def authenticate(
        self, request: Request
    ) -> Union[RedirectResponse, Dict]:
        request_args = await self.prepare_request(request)
        auth = await self.init_saml_auth(request_args)

        if "acs" in request.query_params:
            return await self.assertion_consumer_service(auth, request_args)
        # potentially extend with logout here
        return await self.single_sign_on(auth)

    async def init_saml_auth(self, request_args: Dict) -> OneLogin_Saml2_Auth:
        return OneLogin_Saml2_Auth(
            request_args, custom_base_path=self.custom_folder.as_posix()
        )

    @staticmethod
    async def single_sign_on(auth: OneLogin_Saml2_Auth) -> RedirectResponse:
        redirect_url = auth.login()
        return RedirectResponse(redirect_url)

    @staticmethod
    async def assertion_consumer_service(
        auth: OneLogin_Saml2_Auth, request_args: Dict
    ) -> Union[RedirectResponse, Dict]:
        auth.process_response()
        errors = auth.get_errors()
        if not len(errors) == 0:
            raise SAMLException()
        userdata = {
            "samlUserdata": auth.get_attributes(),
            "samlNameId": auth.get_nameid(),
            "samlNameIdFormat": auth.get_nameid_format(),
            "samlNameIdNameQualifier": auth.get_nameid_nq(),
            "samlNameIdSPNameQualifier": auth.get_nameid_spnq(),
            "samlSessionIndex": auth.get_session_index(),
        }

        self_url = OneLogin_Saml2_Utils.get_self_url(request_args)
        if "RelayState" in request_args.get("post_data") and self_url.rstrip(
            "/"
        ) != request_args.get("post_data", {}).get("RelayState").rstrip("/"):
            return RedirectResponse(
                auth.redirect_to(
                    request_args.get("post_data", {}).get("RelayState")
                )
            )
        else:
            return userdata

    @staticmethod
    async def prepare_request(request: Request):
        return {
            "https": "on" if request.url.scheme == "https" else "off",
            "http_host": request.url.hostname,
            "server_port": request.url.port,
            "script_name": request.url.path,
            "post_data": await request.form()
            # Uncomment if using ADFS
            # "lowercase_urlencoding": True
        }
