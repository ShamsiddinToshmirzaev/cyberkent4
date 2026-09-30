-- Templated: ${DB_NAME}/${DB_PASS} are substituted from db.env by the entrypoint.
-- The empty root password is INTENTIONAL (players log into the hidden console as root/empty).
-- Idempotent: DROP then CREATE, so re-running on every start gives a clean, consistent state.
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('${DB_PASS}');
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;

DROP DATABASE IF EXISTS ${DB_NAME};
CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE ${DB_NAME};

CREATE TABLE `hints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hint` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `hints` VALUES (1, 'Flag serverning maxfiy joyida saqlangan: /tmp/flag.txt');

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(50) NOT NULL,
  `secret` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `users` VALUES
  (1, 'admin', 'Str0ng@Pass#2024!', 'dd02c7c2232759874e1c205587017bed.php'),
  (2, 'guest', 'guest123',          '');
