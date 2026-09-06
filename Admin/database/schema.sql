-- ==========================================================
-- TRES MARIAS CATERING SERVICES - USER & AUTH DATABASE
-- Database Name: tres_marias_user_db
-- Description: Focused ONLY on Login and User Accounts
-- Supports 2 Roles: 'admin' and 'customer' (for future use)
-- ==========================================================

DROP DATABASE IF EXISTS `tres_marias_db`;
CREATE DATABASE IF NOT EXISTS `tres_marias_user_db` 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `tres_marias_user_db`;

-- ==========================================================
-- TABLE: users (For Login and Authentication)
-- ==========================================================
CREATE TABLE IF NOT EXISTS `users` (
  `user_id` INT AUTO_INCREMENT PRIMARY KEY,
  `full_name` VARCHAR(150) NOT NULL,
  `email` VARCHAR(120) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NULL COMMENT 'Hashed password using bcrypt',
  `role` ENUM('admin', 'customer', 'staff') NOT NULL DEFAULT 'customer',
  `phone_number` VARCHAR(25) NULL,
  `avatar_url` VARCHAR(255) NULL,
  
  -- For future customer Google Sign-In
  `google_id` VARCHAR(100) NULL UNIQUE,
  
  -- For 4-Digit Login OTP
  `otp_code` VARCHAR(6) NULL,
  `otp_expires_at` DATETIME NULL,
  
  -- Account Status and Logs
  `status` ENUM('active', 'inactive', 'suspended') NOT NULL DEFAULT 'active',
  `failed_login_attempts` INT NOT NULL DEFAULT 0,
  `lockout_until` DATETIME NULL,
  `failed_otp_attempts` INT NOT NULL DEFAULT 0,
  `otp_lockout_until` DATETIME NULL,
  `last_login` DATETIME NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  
  INDEX `idx_users_email` (`email`),
  INDEX `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ==========================================================
-- DEFAULT SEED ADMIN ACCOUNT
-- Email: admin@email.com
-- Password: Password123
-- OTP: 1234
-- Role: admin
-- ==========================================================
INSERT INTO `users` (
  `user_id`, 
  `full_name`, 
  `email`, 
  `password_hash`, 
  `role`, 
  `phone_number`, 
  `otp_code`, 
  `status`
) VALUES (
  1, 
  'Admin', 
  'admin@email.com', 
  '$2b$10$jd5mcCL4jfBoVNLDHhPoAuzc1rPLkOgYB97ZStwFwt0nvLH5kSlmW', 
  'admin', 
  '0917-000-0000', 
  '1234', 
  'active'
) ON DUPLICATE KEY UPDATE 
  `email` = VALUES(`email`),
  `password_hash` = VALUES(`password_hash`),
  `failed_login_attempts` = 0,
  `lockout_until` = NULL,
  `failed_otp_attempts` = 0,
  `otp_lockout_until` = NULL,
  `otp_code` = VALUES(`otp_code`),
  `otp_expires_at` = NULL,
  `status` = 'active';

