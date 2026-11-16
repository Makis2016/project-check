from .active import ACTIVE_CHECKS
from .auth import check_access_control, check_stored_xss
from .base import CheckContext, CheckFn
from .intrusive import (
    check_command_injection,
    check_path_traversal,
    check_request_smuggling,
    check_ssrf,
    check_ssti,
)
from .passive import PASSIVE_CHECKS
from .quality import check_backup_files, check_csrf, check_graphql, check_host_header, check_page_quality

AUTH_CHECKS = [check_access_control]
INTRUSIVE_CHECKS = [
    check_stored_xss,
    check_ssrf,
    check_path_traversal,
    check_command_injection,
    check_ssti,
    check_request_smuggling,
]
PASSIVE_CHECKS = [
    *PASSIVE_CHECKS,
    check_graphql,
    check_host_header,
    check_csrf,
    check_backup_files,
    check_page_quality,
]

__all__ = [
    "ACTIVE_CHECKS",
    "AUTH_CHECKS",
    "INTRUSIVE_CHECKS",
    "PASSIVE_CHECKS",
    "CheckContext",
    "CheckFn",
]
