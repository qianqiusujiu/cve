-- MySQL 8 shim for MarketplaceKit SQL injection validation (PoC environment only).
-- MySQL 8 removed the legacy spatial function GeomFromText (error 1305: FUNCTION
-- <db>.GeomFromText does not exist). MarketplaceKit (2018-era, Laravel 5.6) targets
-- MySQL 5.6/5.7 servers where GeomFromText(txt) exists. Without this shim every
-- profile save aborts with 1305 BEFORE any expression (including an injected one)
-- is evaluated, which masks the injection on MySQL 8 test instances.
--
-- This stored function restores the MySQL 5.6/5.7 semantics:
--     GeomFromText(txt) === ST_GeomFromText(txt)
--
-- Run it once against the test schema as a privileged user:
--     mysql -u root -p <schema> < mysql8-geomfromtext-shim.sql

DELIMITER $$

DROP FUNCTION IF EXISTS GeomFromText$$
CREATE FUNCTION GeomFromText(t TEXT)
    RETURNS geometry
    DETERMINISTIC
    CONTAINS SQL
    COMMENT 'MySQL 5.6/5.7 compatibility shim (PoC environment only)'
BEGIN
    RETURN ST_GeomFromText(t);
END$$

DELIMITER ;
