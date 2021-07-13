import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict
from typing import Union

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

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
            logger.debug('--sso--')
            return await self.single_sign_on(auth)

        elif 'sso2' in request.query_params:
            logger.debug('--sso2--')
            return_to = '%sattrs/' % request.base_url
            return await self.single_sign_on(auth, return_to)

        elif "acs" in request.query_params:
            logger.debug('--acs--')
            return await self.assertion_consumer_service(auth, request_args, request)

        elif 'slo' in request.query_params:
            logger.debug('--slo--')
            return await self.single_log_out(auth)

        elif 'sls' in request.query_params:
            logger.debug('--sls--')
            return await self.single_log_out_from_IdP(request)

        return await self.single_sign_on(auth)

    async def init_saml_auth(self, request_args: Dict) -> OneLogin_Saml2_Auth:
        return OneLogin_Saml2_Auth(
            request_args, custom_base_path=self.custom_folder.as_posix()
        )

    @staticmethod
    async def single_log_out_from_IdP(request: Request) -> \
        Union[RedirectResponse, Dict]:
        req_args = await SAMLAuthentication.prepare_request(request)
        if not req_args['get_data'].get('SAMLResponse') and request.query_params.get('SAMLResponse'):
            req_args['get_data'] = {'SAMLResponse': request.query_params.get('SAMLResponse')}
        auth = await SAMLAuthentication.init_saml_auth(req_args)
        dscb = lambda: request.session.clear()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return RedirectResponse(url)
            else:
                return {'success_slo': True}
        else:
            return {'error': auth.get_last_error_reason()}

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
            raise SAMLException(auth.get_last_error_reason())
        userdata = {
            "samlUserdata": auth.get_attributes(),
            "samlNameId": auth.get_nameid(),
            "samlNameIdFormat": auth.get_nameid_format(),
            "samlNameIdNameQualifier": auth.get_nameid_nq(),
            "samlNameIdSPNameQualifier": auth.get_nameid_spnq(),
            "samlSessionIndex": auth.get_session_index(),
        }
        request.session['saml_session'] = json.dumps(userdata)

        self_url = OneLogin_Saml2_Utils.get_self_url(request_args)
        if "RelayState" in request_args.get("post_data") and self_url.rstrip(
            "/"
        ) != request_args.get("post_data", {}).get("RelayState").rstrip("/"):
            return RedirectResponse(
                auth.redirect_to(
                    request_args.get("post_data", {}).get("RelayState")
                )
            )

        return userdata

    @staticmethod
    async def prepare_request(request: Request):
        form_data = await request.form()
        return {
            "https": "on" if request.url.scheme == "https" else "off",
            "http_host": request.url.hostname,
            "server_port": request.url.port,
            "script_name": request.url.path,
            "post_data": form_data,
            # Uncomment if using ADFS
            # "lowercase_urlencoding": True,
            'get_data': form_data
        }

    async def get_metadata(self, request: Request):
        saml_settings = OneLogin_Saml2_Settings(custom_base_path=self.custom_folder,
                                                sp_validation_only=True)
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)
        status_code = 200
        if len(errors) != 0:
            metadata = ', '.join(errors)
            status_code = 500
        return Response(content=metadata, media_type="application/xml", status_code=status_code)
