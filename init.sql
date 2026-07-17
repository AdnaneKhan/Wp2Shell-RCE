-- Grants the WP DB user the global FILE privilege (a PRECONDITION for the INTO OUTFILE
-- RCE variant demonstrated here — NOT the WP default).
-- Note: cPanel/managed hosts grant `ALL ON wordpressdb.*` (per-database), which does
-- NOT include FILE. FILE shows up on self-managed VPS / DIY LAMP-LEMP stacks that run
-- `GRANT ALL ON *.*`, and in dev boxes. This lab grants it to reproduce that variant.
GRANT FILE ON *.* TO 'wordpress'@'%';
FLUSH PRIVILEGES;
