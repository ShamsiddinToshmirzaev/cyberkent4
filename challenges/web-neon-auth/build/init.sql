-- Templated: ${DB_NAME}/${DB_USER}/${DB_PASS} are substituted from db.env by the entrypoint.
-- Idempotent: DROP then CREATE, so re-running on every start gives a clean, consistent state.
DROP DATABASE IF EXISTS ${DB_NAME};
CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

DROP USER IF EXISTS '${DB_USER}'@'127.0.0.1';
CREATE USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT SELECT ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';
-- FILE priv is the intended vuln surface (enables LOAD_FILE for the flag read).
GRANT FILE ON *.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;

USE ${DB_NAME};

CREATE TABLE users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL
);

INSERT INTO users (username, password) VALUES
    ('admin',  'n0t_that_3asy'),
    ('guest',  'guest123'),
    ('viewer', 'readonly99');
