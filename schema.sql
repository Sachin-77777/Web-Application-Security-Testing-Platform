-- Web Application Security Testing Platform
-- MySQL schema

CREATE DATABASE IF NOT EXISTS wastp
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE wastp;

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(80) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'user', 'client') NOT NULL DEFAULT 'client',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS applications (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(150) NOT NULL,
  target_url VARCHAR(2048) NOT NULL,
  description TEXT,
  owner_id INT UNSIGNED NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_applications_owner_id (owner_id),
  CONSTRAINT fk_applications_owner
    FOREIGN KEY (owner_id) REFERENCES users (id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS test_cases (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  app_id INT UNSIGNED NOT NULL,
  test_name VARCHAR(200) NOT NULL,
  category VARCHAR(100) NOT NULL,
  status ENUM('Pending', 'Passed', 'Failed') NOT NULL DEFAULT 'Pending',
  assigned_to INT UNSIGNED DEFAULT NULL,
  PRIMARY KEY (id),
  KEY ix_test_cases_app_id (app_id),
  KEY ix_test_cases_assigned_to (assigned_to),
  CONSTRAINT fk_test_cases_application
    FOREIGN KEY (app_id) REFERENCES applications (id)
    ON UPDATE CASCADE
    ON DELETE CASCADE,
  CONSTRAINT fk_test_cases_assignee
    FOREIGN KEY (assigned_to) REFERENCES users (id)
    ON UPDATE CASCADE
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  app_id INT UNSIGNED NOT NULL,
  title VARCHAR(255) NOT NULL,
  severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
  cvss_score DECIMAL(3,1) DEFAULT NULL,
  status ENUM('Open', 'Fixed') NOT NULL DEFAULT 'Open',
  owasp_category VARCHAR(100) DEFAULT NULL,
  cwe_id VARCHAR(20) DEFAULT NULL,
  evidence TEXT,
  remediation TEXT,
  description TEXT,
  PRIMARY KEY (id),
  KEY ix_vulnerabilities_app_id (app_id),
  KEY ix_vulnerabilities_severity (severity),
  CONSTRAINT fk_vulnerabilities_application
    FOREIGN KEY (app_id) REFERENCES applications (id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reports (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  app_id INT UNSIGNED NOT NULL,
  generated_by INT UNSIGNED NOT NULL,
  report_path VARCHAR(1024) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_reports_app_id (app_id),
  KEY ix_reports_generated_by (generated_by),
  CONSTRAINT fk_reports_application
    FOREIGN KEY (app_id) REFERENCES applications (id)
    ON UPDATE CASCADE
    ON DELETE CASCADE,
  CONSTRAINT fk_reports_generated_by
    FOREIGN KEY (generated_by) REFERENCES users (id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Single-use, expiring password-reset codes. Only the hash of a code is
-- stored, never the code itself.
CREATE TABLE IF NOT EXISTS password_reset_otps (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  code_hash VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  consumed_at DATETIME DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_password_reset_otps_user_id (user_id),
  CONSTRAINT fk_password_reset_otps_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON UPDATE CASCADE
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
