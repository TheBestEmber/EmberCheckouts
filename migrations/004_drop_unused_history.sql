DROP TABLE checkout_events;

ALTER TABLE checkouts
    DROP COLUMN proxy_used,
    DROP COLUMN event_count;
