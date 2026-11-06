from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from constants import USER_ROLES
from extensions import db


def utcnow():
    return datetime.now(timezone.utc)


def utcnow_naive():
    """Naive UTC, for columns that are compared rather than just displayed.

    MySQL and SQLite hand ``DateTime`` columns back without a timezone, so
    comparing them against an aware datetime raises ``TypeError``. Storing and
    comparing naive UTC keeps both engines on the same footing.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(*USER_ROLES), nullable=False, default="client")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    applications = db.relationship(
        "Application",
        back_populates="owner",
        foreign_keys="Application.owner_id",
    )
    assigned_tests = db.relationship(
        "TestCase",
        back_populates="assignee",
        foreign_keys="TestCase.assigned_to",
    )
    reports = db.relationship(
        "Report",
        back_populates="author",
        foreign_keys="Report.generated_by",
    )
    password_reset_codes = db.relationship(
        "PasswordResetOTP",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_client(self):
        """Clients submit applications and read reports, but never run tests."""
        return self.role == "client"

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User {self.username}>"


class Application(db.Model):
    __tablename__ = "applications"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    target_url = db.Column(db.String(2048), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    owner = db.relationship("User", back_populates="applications")
    test_cases = db.relationship(
        "TestCase",
        back_populates="application",
        cascade="all, delete-orphan",
    )
    vulnerabilities = db.relationship(
        "Vulnerability",
        back_populates="application",
        cascade="all, delete-orphan",
    )
    reports = db.relationship(
        "Report",
        back_populates="application",
        cascade="all, delete-orphan",
    )


class TestCase(db.Model):
    __tablename__ = "test_cases"
    __test__ = False  # Tell pytest this is a data model, not a test class.

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    test_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    status = db.Column(
        db.Enum("Pending", "Passed", "Failed"),
        nullable=False,
        default="Pending",
    )
    assigned_to = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    application = db.relationship("Application", back_populates="test_cases")
    assignee = db.relationship("User", back_populates="assigned_tests")


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(
        db.Enum("Low", "Medium", "High", "Critical"),
        nullable=False,
    )
    cvss_score = db.Column(db.Numeric(3, 1), nullable=True)
    status = db.Column(
        db.Enum("Open", "Fixed"),
        nullable=False,
        default="Open",
    )
    # Optional classification and evidence that make a finding actionable.
    owasp_category = db.Column(db.String(100), nullable=True)
    cwe_id = db.Column(db.String(20), nullable=True)
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    description = db.Column(db.Text)

    application = db.relationship("Application", back_populates="vulnerabilities")


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    generated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    report_path = db.Column(db.String(1024), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    application = db.relationship("Application", back_populates="reports")
    author = db.relationship("User", back_populates="reports")


class PasswordResetOTP(db.Model):
    """A single-use, expiring password-reset code for one account.

    The code itself is never stored: only a hash of it, so a leaked database
    dump does not hand an attacker a working reset code. ``attempts`` caps how
    many guesses a code tolerates, which is what stops someone brute-forcing a
    six-digit number in the ten minutes it stays valid.
    """

    __tablename__ = "password_reset_otps"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    consumed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)

    user = db.relationship("User", back_populates="password_reset_codes")

    def set_code(self, code):
        self.code_hash = generate_password_hash(code)

    def check_code(self, code):
        return check_password_hash(self.code_hash, code)

    def is_expired(self, now=None):
        now = now or utcnow_naive()
        return self.expires_at <= now

    def is_usable(self, max_attempts, now=None):
        """True only while the code is unconsumed, unexpired and in attempts."""
        if self.consumed_at is not None:
            return False
        if self.attempts >= max_attempts:
            return False
        return not self.is_expired(now)

    def __repr__(self):
        return f"<PasswordResetOTP user={self.user_id}>"
