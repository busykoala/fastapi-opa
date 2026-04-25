import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from typing import cast
from urllib.parse import urlparse
from urllib.parse import urlunparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from starlette.requests import Request
from starlette.responses import RedirectResponse

from fastapi_opa.auth.auth_interface import AuthInterface
from fastapi_opa.auth.exceptions import SAMLException
from fastapi_opa.models import AuthenticationResult

logger = logging.getLogger(__name__)

RequestData = dict[str, object]


def _combine_uri_paths(base_path: str, request_path: str) -> str:
    normalized_request_path = (
        request_path if request_path.startswith("/") else f"/{request_path}"
    )
    normalized_base_path = base_path.rstrip("/")

    if not normalized_base_path:
        return normalized_request_path
    if normalized_request_path == normalized_base_path:
        return normalized_request_path
    if normalized_request_path.startswith(f"{normalized_base_path}/"):
        return normalized_request_path
    if normalized_request_path == "/":
        return f"{normalized_base_path}/"
    return f"{normalized_base_path}{normalized_request_path}"


class SAMLAuthProtocol(Protocol):
    def get_nameid(self) -> str | None: ...

    def get_session_index(self) -> str | None: ...

    def get_nameid_format(self) -> str | None: ...

    def get_nameid_spnq(self) -> str | None: ...

    def get_nameid_nq(self) -> str | None: ...

    def logout(
        self,
        *,
        name_id: str | None = None,
        session_index: str | None = None,
        nq: str | None = None,
        name_id_format: str | None = None,
        spnq: str | None = None,
    ) -> str: ...

    def login(self, return_to: str | None = None) -> str: ...

    def process_response(self) -> None: ...

    def get_errors(self) -> list[str]: ...

    def get_last_error_reason(self) -> str: ...

    def get_attributes(self) -> dict[str, object]: ...

    def process_slo(
        self, delete_session_cb: Callable[[], None]
    ) -> str | None: ...

    def redirect_to(self, url: str) -> str: ...


@dataclass
class SAMLConfig:
    settings_directory: str
    app_uri: str | None = None

    def __post_init__(self) -> None:
        if self.app_uri is None:
            return

        parsed_app_uri = urlparse(self.app_uri)
        if (
            parsed_app_uri.scheme not in {"http", "https"}
            or not parsed_app_uri.netloc
            or parsed_app_uri.params
            or parsed_app_uri.query
            or parsed_app_uri.fragment
        ):
            raise SAMLException(
                "app_uri must be an absolute http(s) URL without params, "
                "query, or fragment",
            )


class SAMLAuthentication(AuthInterface):
    def __init__(self, config: SAMLConfig):
        self.config = config
        self.custom_folder = Path(self.config.settings_directory)

    async def authenticate(
        self,
        request: Request,
        accepted_methods: list[str] | None = None,
    ) -> RedirectResponse | AuthenticationResult:
        request_args = await self.prepare_request(request, self.config)
        auth = await self.init_saml_auth(request_args)

        if "sso" in request.query_params:
            logger.debug("--sso--")
            return await self.single_sign_on(auth)

        if "sso2" in request.query_params:
            logger.debug("--sso2--")
            return_to = self._build_absolute_uri(request, "/attrs/")
            return await self.single_sign_on(auth, return_to)

        if "acs" in request.query_params:
            logger.debug("--acs--")
            return await self.assertion_consumer_service(
                auth, request_args, request
            )

        if "slo" in request.query_params:
            logger.debug("--slo--")
            return await self.single_log_out(auth)

        if "sls" in request.query_params:
            logger.debug("--sls--")
            return await self.single_log_out_from_idp(request)

        return await self.single_sign_on(auth)

    def _build_absolute_uri(self, request: Request, request_path: str) -> str:
        if self.config.app_uri is None:
            return urlunparse(
                (
                    request.url.scheme,
                    request.url.netloc,
                    request_path,
                    "",
                    "",
                    "",
                )
            )

        parsed_app_uri = urlparse(self.config.app_uri)
        return urlunparse(
            (
                parsed_app_uri.scheme,
                parsed_app_uri.netloc,
                _combine_uri_paths(parsed_app_uri.path, request_path),
                "",
                "",
                "",
            )
        )

    async def init_saml_auth(
        self, request_args: RequestData
    ) -> SAMLAuthProtocol:
        return cast(
            SAMLAuthProtocol,
            OneLogin_Saml2_Auth(
                request_args, custom_base_path=self.custom_folder.as_posix()
            ),
        )

    async def single_log_out_from_idp(
        self, request: Request
    ) -> RedirectResponse | AuthenticationResult:
        req_args = await self.prepare_request(request, self.config)
        get_data = req_args.get("get_data")
        saml_response = request.query_params.get("SAMLResponse")
        existing_saml_response = (
            cast(dict[str, object], get_data).get("SAMLResponse")
            if isinstance(get_data, dict)
            else None
        )
        if not existing_saml_response and saml_response:
            req_args["get_data"] = {"SAMLResponse": saml_response}
        auth = await self.init_saml_auth(req_args)
        dscb = lambda: request.session.clear()  # noqa
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return RedirectResponse(url)
            return AuthenticationResult(
                success=True, user_info={"success_slo": True}
            )
        return AuthenticationResult(
            success=False, error=auth.get_last_error_reason()
        )

    @staticmethod
    async def single_log_out(auth: SAMLAuthProtocol) -> RedirectResponse:
        name_id = auth.get_nameid()
        session_index = auth.get_session_index()
        name_id_format = auth.get_nameid_format()
        name_id_spnq = auth.get_nameid_spnq()
        name_id_nq = auth.get_nameid_nq()
        return RedirectResponse(
            auth.logout(
                name_id=name_id,
                session_index=session_index,
                nq=name_id_nq,
                name_id_format=name_id_format,
                spnq=name_id_spnq,
            ),
            status_code=303,
        )

    @staticmethod
    async def single_sign_on(
        auth: SAMLAuthProtocol, url: str | None = None
    ) -> RedirectResponse:
        redirect_url = auth.login(url)
        return RedirectResponse(redirect_url, status_code=303)

    @staticmethod
    def _is_safe_relay_state(relay_state: str, self_url: str) -> bool:
        """Allow only relative URLs or absolute URLs on the same origin."""
        if not relay_state:
            return False

        relay = urlparse(relay_state)
        if not relay.scheme and not relay.netloc:
            return relay_state.startswith("/")

        if relay.scheme not in {"http", "https"}:
            return False

        current = urlparse(self_url)
        return (
            relay.scheme == current.scheme and relay.netloc == current.netloc
        )

    @staticmethod
    async def assertion_consumer_service(
        auth: SAMLAuthProtocol,
        request_args: RequestData,
        request: Request,
    ) -> RedirectResponse | AuthenticationResult:
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
        request.session["saml_session"] = json.dumps(userdata)

        self_url = OneLogin_Saml2_Utils.get_self_url(request_args)
        post_data = request_args.get("post_data", {})
        relay_state: str | None = None
        if isinstance(post_data, dict):
            relay_state_value = cast(dict[str, object], post_data).get(
                "RelayState"
            )
            if isinstance(relay_state_value, str):
                relay_state = relay_state_value
        if relay_state and self_url.rstrip("/") != relay_state.rstrip("/"):
            if SAMLAuthentication._is_safe_relay_state(relay_state, self_url):
                return RedirectResponse(
                    auth.redirect_to(relay_state),
                    status_code=303,
                )

            logger.warning(
                "Blocked unsafe RelayState redirect target during ACS flow"
            )

        return AuthenticationResult(
            success=True,
            user_info=cast(dict[str, object], userdata),
        )

    @staticmethod
    async def prepare_request(
        request: Request, config: SAMLConfig | None = None
    ) -> RequestData:
        form_data = await request.form()
        if config is not None and config.app_uri is not None:
            parsed_app_uri = urlparse(config.app_uri)
            request_scheme = parsed_app_uri.scheme
            request_host = parsed_app_uri.hostname
            request_port = parsed_app_uri.port
            if request_port is None:
                request_port = 443 if request_scheme == "https" else 80
            request_path = _combine_uri_paths(
                parsed_app_uri.path,
                request.url.path,
            )
        else:
            request_scheme = request.url.scheme
            request_host = request.url.hostname
            request_port = request.url.port
            request_path = request.url.path

        return {
            "https": "on" if request_scheme == "https" else "off",
            "http_host": request_host,
            "server_port": request_port,
            "script_name": request_path,
            "post_data": form_data,
            # Uncomment if using ADFS
            # "lowercase_urlencoding": True,
            "get_data": form_data,
        }
