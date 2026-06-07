-- ─────────────────────────────────────────────────────────────────────────────
--  Orbital Trust · esquema de persistência (PostgreSQL)
--
--  A tabela armazena leituras de sensores. O campo `coordenada` é o dado mais
--  sensível (localização exata da infraestrutura monitorada) e por isso NUNCA é
--  gravado em texto claro: a aplicação grava o ciphertext Base64 do AES-256-GCM.
--
--  O tipo TEXT acomoda o formato serializado nonce(12) | tag(16) | ciphertext,
--  codificado em Base64 pelo CryptoService.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS leituras_sensor (
    id           SERIAL PRIMARY KEY,
    sensor_nome  TEXT        NOT NULL,
    -- Coordenada SEMPRE criptografada (AES-256-GCM, Base64). Nunca texto claro.
    coordenada   TEXT        NOT NULL,
    capturado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN leituras_sensor.coordenada IS
    'Dado sensível cifrado com AES-256-GCM (formato Base64: nonce|tag|ciphertext). Jamais armazenar texto claro.';
