"""ThurSec security-awareness subsystem.

The *legitimate* counterpart to phishing: tooling to train an organization's
own staff to recognize scams. By design this package never captures credentials
and never sends e-mail. See :mod:`thursec.awareness.campaign` for details and
the ethical gates (recorded authorization + recipient allowlist) it enforces.
"""

from __future__ import annotations

from .campaign import (
    AllowlistError,
    Allowlist,
    Authorization,
    AuthorizationError,
    AwarenessError,
    Campaign,
    RecipientToken,
    build_tracking_url,
    render_email_template,
    render_landing_page,
    tally_clicks,
)

__all__ = [
    "AwarenessError",
    "AuthorizationError",
    "AllowlistError",
    "Authorization",
    "Allowlist",
    "Campaign",
    "RecipientToken",
    "build_tracking_url",
    "render_landing_page",
    "render_email_template",
    "tally_clicks",
]
