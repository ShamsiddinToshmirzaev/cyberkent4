-- Templated: ${DB_NAME}/${DB_USER}/${DB_PASS} substituted from db.env by the entrypoint.
-- Idempotent: DROP then CREATE, so every start gives a clean, consistent state.
DROP DATABASE IF EXISTS ${DB_NAME};
CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

DROP USER IF EXISTS '${DB_USER}'@'127.0.0.1';
CREATE USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT SELECT ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;

USE ${DB_NAME};

CREATE TABLE demo (
    id   INT AUTO_INCREMENT PRIMARY KEY,
    note VARCHAR(100) NOT NULL
);
INSERT INTO demo (note) VALUES ('replace this demo table with your challenge schema');
