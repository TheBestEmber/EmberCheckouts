ALTER TABLE checkouts
    ADD COLUMN location text NOT NULL DEFAULT '' CHECK (char_length(location) <= 200),
    ADD COLUMN event_date text NOT NULL DEFAULT '' CHECK (char_length(event_date) <= 64),
    ADD COLUMN seating text NOT NULL DEFAULT '' CHECK (char_length(seating) <= 500),
    ADD COLUMN mode text NOT NULL DEFAULT '' CHECK (char_length(mode) <= 64),
    ADD COLUMN order_number text NOT NULL DEFAULT '' CHECK (char_length(order_number) <= 64);
