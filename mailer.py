"""Delivery of password-reset codes.

When ``MAIL_SERVER`` is configured the code goes out over SMTP. In the local
lab there is no mail server, so the mailer writes the code to the application
log instead and the reset flow stays demonstrable end to end.

Only the delivery changes between the two modes; the calling code does not
care which one ran.
"""

import smtplib
from email.message import EmailMessage

from flask import current_app


def _compose(to_email, code, minutes):
    message = EmailMessage()
    message["Subject"] = "Your WASTP password reset code"
    message["From"] = current_app.config["MAIL_FROM"]
    message["To"] = to_email
    message.set_content(
        "\n".join(
            [
                "A password reset was requested for your WASTP account.",
                "",
                f"Your reset code is: {code}",
                "",
                f"The code expires in {minutes} minutes and can be used once.",
                "If you did not request this, you can ignore this message.",
            ]
        )
    )
    return message


def send_password_reset_code(to_email, code):
    """Deliver ``code`` to ``to_email``. Returns the transport that was used."""
    minutes = current_app.config["PASSWORD_RESET_OTP_MINUTES"]
    server = current_app.config.get("MAIL_SERVER")

    if not server:
        # Dev transport: the code lands in the console running `python app.py`.
        current_app.logger.warning(
            "PASSWORD RESET CODE for %s is %s (valid %s minutes) - "
            "no MAIL_SERVER configured, so it was written here instead of emailed.",
            to_email,
            code,
            minutes,
        )
        return "log"

    message = _compose(to_email, code, minutes)
    port = current_app.config["MAIL_PORT"]
    with smtplib.SMTP(server, port, timeout=10) as smtp:
        if current_app.config.get("MAIL_USE_TLS"):
            smtp.starttls()
        username = current_app.config.get("MAIL_USERNAME")
        if username:
            smtp.login(username, current_app.config.get("MAIL_PASSWORD") or "")
        smtp.send_message(message)
    return "smtp"
