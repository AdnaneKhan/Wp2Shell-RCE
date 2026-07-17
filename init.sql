-- Grants the WP DB user the global FILE privilege.
-- This mirrors the extremely common shared-hosting / cPanel misconfiguration where
-- the WordPress MySQL account is created with ALL PRIVILEGES (FILE included).
-- FILE + the default secure_file_priv dir is what makes a SELECT-injection able to
-- write a PHP file (INTO OUTFILE) -> the SQLi -> RCE step.
GRANT FILE ON *.* TO 'wordpress'@'%';
FLUSH PRIVILEGES;
