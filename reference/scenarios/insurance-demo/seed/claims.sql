-- Insurance claims fixture for the multi-surface demo.
--
-- Schema mirrors a realistic auto-insurance claims table with the
-- ``cross_company_flag`` column the night-reporter agent queries on.
-- Intentionally small (12 rows) so the LLM tool call stays cheap and
-- the recording stays watchable.

CREATE TABLE IF NOT EXISTS claims (
    claim_id              VARCHAR(32) PRIMARY KEY,
    incident_date         DATE NOT NULL,
    region                VARCHAR(64) NOT NULL,
    insured_party         VARCHAR(128) NOT NULL,
    counterparty          VARCHAR(128),
    counterparty_insurer  VARCHAR(64),
    estimated_amount_eur  INTEGER NOT NULL,
    cross_company_flag    BOOLEAN NOT NULL DEFAULT FALSE,
    urgency               VARCHAR(16) NOT NULL DEFAULT 'normal',  -- low | normal | high
    status                VARCHAR(32) NOT NULL DEFAULT 'open',
    notes                 TEXT
);

CREATE INDEX IF NOT EXISTS idx_claims_cross_company ON claims (cross_company_flag);
CREATE INDEX IF NOT EXISTS idx_claims_urgency       ON claims (urgency);
CREATE INDEX IF NOT EXISTS idx_claims_status        ON claims (status);

-- 12 claims: 3 cross-company high-urgency (the ones night-reporter
-- escalates), 3 cross-company normal, 6 same-company routine.
INSERT INTO claims VALUES
('INC-2026-0501', '2026-04-15', 'Lazio',     'Rossi Daniele',         'Tanaka Hiroshi',     'Asia-Pacific Insurance', 18500, TRUE,  'high',   'open',         'Multi-vehicle accident A1 Roma–Napoli, counterparty insured in Tokyo'),
('INC-2026-0502', '2026-04-18', 'Lombardia', 'Bianchi Marco',         'Yamamoto Aiko',      'Asia-Pacific Insurance', 42000, TRUE,  'high',   'open',         'Total loss, BMW vs rental car driven by JP tourist'),
('INC-2026-0503', '2026-04-22', 'Campania',  'Esposito Sara',         'Sato Kenji',         'Asia-Pacific Insurance', 7800,  TRUE,  'high',   'open',         'Parking damage, counterparty insured by partner Asia-Pacific'),
('INC-2026-0504', '2026-04-10', 'Piemonte',  'Ferrari Lucia',         'Nakamura Yuki',      'Asia-Pacific Insurance', 3200,  TRUE,  'normal', 'open',         'Fender bender, low priority cross-company'),
('INC-2026-0505', '2026-04-12', 'Veneto',    'Russo Antonio',         'Suzuki Hana',        'Asia-Pacific Insurance', 2100,  TRUE,  'normal', 'open',         'Mirror replacement, cross-company'),
('INC-2026-0506', '2026-04-19', 'Toscana',   'De Luca Maria',         'Watanabe Sora',      'Asia-Pacific Insurance', 5400,  TRUE,  'normal', 'open',         'Door panel, cross-company'),
('INC-2026-0507', '2026-04-08', 'Emilia',    'Galli Marco',           'Verde Anna',         NULL,                     1200,  FALSE, 'low',    'pending_paid', 'Internal — both parties Mediterranean Insurance'),
('INC-2026-0508', '2026-04-09', 'Lazio',     'Marini Roberto',        'Bianchi Carla',      NULL,                     2800,  FALSE, 'normal', 'open',         'Internal claim'),
('INC-2026-0509', '2026-04-11', 'Sicilia',   'Conte Filippo',         'Greco Federica',     NULL,                     6500,  FALSE, 'normal', 'open',         'Internal claim'),
('INC-2026-0510', '2026-04-14', 'Puglia',    'Costa Marco',           'Ricci Chiara',       NULL,                     900,   FALSE, 'low',    'pending_paid', 'Internal claim'),
('INC-2026-0511', '2026-04-16', 'Calabria',  'Romano Stefania',       'Vitali Luigi',       NULL,                     14200, FALSE, 'high',   'open',         'Internal — total loss'),
('INC-2026-0512', '2026-04-20', 'Liguria',   'Lombardi Alessandro',   'Fontana Valeria',    NULL,                     3400,  FALSE, 'normal', 'open',         'Internal claim')
ON CONFLICT (claim_id) DO NOTHING;
