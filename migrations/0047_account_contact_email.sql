-- Optional account contact data accepted by draft/account-registration and
-- NickServ. The application parses the full mailbox shape; this constraint is
-- the storage backstop against unbounded or control-bearing legacy writes.

ALTER TABLE accounts
    ADD COLUMN contact_email TEXT,
    ADD CONSTRAINT accounts_contact_email_shape
        CHECK (
            contact_email IS NULL
            OR (
                octet_length(contact_email) BETWEEN 3 AND 254
                AND contact_email !~ '[[:cntrl:][:space:]]'
            )
        );
