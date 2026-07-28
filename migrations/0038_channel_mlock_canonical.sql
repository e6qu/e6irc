-- One durable spelling for one MLOCK policy. Earlier builds preserved input
-- order, so normalize existing valid rows before constraining future writes.
DO $$
DECLARE
    row RECORD;
    adding BOOLEAN;
    position_index INTEGER;
    mode TEXT;
    on_modes TEXT;
    off_modes TEXT;
    canonical TEXT;
BEGIN
    FOR row IN SELECT id, mlock FROM channels WHERE mlock IS NOT NULL LOOP
        adding := TRUE;
        on_modes := '';
        off_modes := '';
        FOR position_index IN 1..char_length(row.mlock) LOOP
            mode := substr(row.mlock, position_index, 1);
            IF mode = '+' THEN
                adding := TRUE;
            ELSIF mode = '-' THEN
                adding := FALSE;
            ELSIF position(mode IN 'imnstC') > 0 THEN
                on_modes := replace(on_modes, mode, '');
                off_modes := replace(off_modes, mode, '');
                IF adding THEN
                    on_modes := on_modes || mode;
                ELSE
                    off_modes := off_modes || mode;
                END IF;
            ELSE
                RAISE EXCEPTION 'invalid persisted MLOCK character % in %', mode, row.mlock;
            END IF;
        END LOOP;

        canonical := '';
        mode := '';
        FOREACH mode IN ARRAY ARRAY['i', 'm', 'n', 's', 't', 'C'] LOOP
            IF position(mode IN on_modes) > 0 THEN
                canonical := canonical || mode;
            END IF;
        END LOOP;
        IF canonical <> '' THEN
            canonical := '+' || canonical;
        END IF;
        on_modes := canonical;
        canonical := '';
        FOREACH mode IN ARRAY ARRAY['i', 'm', 'n', 's', 't', 'C'] LOOP
            IF position(mode IN off_modes) > 0 THEN
                canonical := canonical || mode;
            END IF;
        END LOOP;
        IF canonical <> '' THEN
            canonical := '-' || canonical;
        END IF;
        canonical := on_modes || canonical;
        IF canonical = '' THEN
            UPDATE channels SET mlock = NULL WHERE id = row.id;
        ELSE
            UPDATE channels SET mlock = canonical WHERE id = row.id;
        END IF;
    END LOOP;
END $$;

ALTER TABLE channels
    ADD CONSTRAINT channels_mlock_canonical
    CHECK (
        mlock IS NULL
        OR (
            mlock <> ''
            AND mlock ~ '^([+]i?m?n?s?t?C?)?(-i?m?n?s?t?C?)?$'
            AND mlock !~ '[+-]$'
            AND mlock !~ '[+]-'
            AND mlock !~ '(i.*i|m.*m|n.*n|s.*s|t.*t|C.*C)'
        )
    );
