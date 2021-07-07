import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict
from typing import Union

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import SAMLException

logger = logging.getLogger(__name__)


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

        if 'sso' in request.query_params:
            logger.debug(datetime.utcnow(), '--sso--')
            return await self.single_sign_on(auth)

        elif 'sso2' in request.query_params:
            logger.debug(datetime.utcnow(), '--sso2--')
            return_to = '%sattrs/' % request.base_url
            return await self.single_sign_on(auth, return_to)

        elif "acs" in request.query_params:
            logger.debug(datetime.utcnow(), '--acs--')
            return await self.assertion_consumer_service(auth, request_args, request)

        elif 'slo' in request.query_params:
            logger.debug(datetime.utcnow(), '--slo--')
            del request.session['saml_session']
            return await self.single_log_out(auth)

        elif 'sls' in request.query_params:
            logger.debug(datetime.utcnow(), '--sls--')
            return await self.single_log_out_from_IdP(auth, request)

        return await self.single_sign_on(auth)

    async def init_saml_auth(self, request_args: Dict) -> OneLogin_Saml2_Auth:
        return OneLogin_Saml2_Auth(
            request_args, custom_base_path=self.custom_folder.as_posix()
        )

    @staticmethod
    async def single_log_out_from_IdP(auth: OneLogin_Saml2_Auth, request: Request) -> \
        Union[RedirectResponse, Dict]:
        data = request.query_params
        request_id = data.get('post_data').get('LogoutRequestID', None)

        def request_session_flush(request):
            if request.session.get('saml_session'):
                request.session['saml_session'] = None

        dscb = request_session_flush(request)
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return RedirectResponse(url)
            else:
                return await SAMLAuthentication.single_sign_on(auth)
        else:
            error_reason = auth.get_last_error_reason()
            return {'error': error_reason}

    @staticmethod
    async def single_log_out(auth: OneLogin_Saml2_Auth) -> RedirectResponse:
        name_id = auth.get_nameid()
        session_index = auth.get_session_index()
        name_id_format = auth.get_nameid_format()
        name_id_spnq = auth.get_nameid_spnq()
        name_id_nq = auth.get_nameid_nq()
        return RedirectResponse(
            auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format,
                        spnq=name_id_spnq))

    @staticmethod
    async def single_sign_on(auth: OneLogin_Saml2_Auth, url: str = None) -> RedirectResponse:
        redirect_url = auth.login(url)
        return RedirectResponse(redirect_url)

    @staticmethod
    async def assertion_consumer_service(
        auth: OneLogin_Saml2_Auth, request_args: Dict, request: Request
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
        request.session['saml_session'] = json.dumps(userdata)
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
