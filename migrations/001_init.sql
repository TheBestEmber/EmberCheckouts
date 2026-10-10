BEGIN;

CREATE TABLE IF NOT EXISTS checkouts (
    id uuid PRIMARY KEY,
    owner_subject text NOT NULL CHECK (char_length(owner_subject) BETWEEN 1 AND 255),
    membership_id text NOT NULL CHECK (char_length(membership_id) BETWEEN 1 AND 255),
    installation_id text NOT NULL CHECK (char_length(installation_id) BETWEEN 1 AND 255),
    session_id text NOT NULL CHECK (char_length(session_id) BETWEEN 1 AND 255),
    module text NOT NULL CHECK (char_length(module) BETWEEN 1 AND 64),
    site text NOT NULL CHECK (char_length(site) BETWEEN 1 AND 64),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    quantity integer NOT NULL CHECK (quantity BETWEEN 0 AND 100000),
    price text NOT NULL CHECK (char_length(price) <= 32),
    currency text NOT NULL CHECK (currency = '' OR currency ~ '^[A-Z]{3}$'),
    producer_version text NOT NULL CHECK (char_length(producer_version) BETWEEN 1 AND 64),
    target_host text NOT NULL CHECK (char_length(target_host) BETWEEN 1 AND 253),
    proxy_used boolean NOT NULL,
    retrieval_count bigint NOT NULL DEFAULT 0 CHECK (retrieval_count >= 0),
    event_count smallint NOT NULL DEFAULT 0 CHECK (event_count BETWEEN 0 AND 20),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    envelope_version integer,
    encryption_key_id text,
    nonce bytea,
    ciphertext bytea,
    CHECK (expires_at = created_at + interval '10 minutes'),
    CHECK (
        (ciphertext IS NULL AND nonce IS NULL AND encryption_key_id IS NULL AND envelope_version IS NULL)
        OR
        (ciphertext IS NOT NULL AND nonce IS NOT NULL AND encryption_key_id IS NOT NULL AND envelope_version IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS checkout_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    checkout_id uuid NOT NULL REFERENCES checkouts(id) ON DELETE RESTRICT,
    outcome text NOT NULL CHECK (outcome IN (
        'import_succeeded',
        'import_partial',
        'invalid_payload',
        'permissions_denied',
        'cookies_failed',
        'local_storage_failed',
        'session_storage_failed',
        'proxy_failed',
        'navigation_failed',
        'unsupported_browser_state'
    )),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS checkouts_expiry_idx
    ON checkouts (expires_at)
    WHERE ciphertext IS NOT NULL;
CREATE INDEX IF NOT EXISTS checkouts_membership_created_idx
    ON checkouts (membership_id, created_at DESC);
CREATE INDEX IF NOT EXISTS checkout_events_checkout_idx
    ON checkout_events (checkout_id, created_at);

COMMIT;
