-- Wingman v3.0.0 — Postgres schema
-- Executed by server.py on every startup. Every statement is idempotent
-- (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS), so it is safe to re-run.
--
-- Conventions
--   * App-facing timestamps that Notion stored as ISO strings (saved_at, reviewed_at, ...)
--     stay TEXT so they round-trip byte-for-byte and the verify check can compare exactly.
--     Server bookkeeping timestamps are TIMESTAMPTZ.
--   * notion_page_id / notion_raw exist only on rows that came from the one-time import.
--     notion_raw is the complete property map as read from Notion at import time.
--   * app_updated_at is NULL until Wingman itself writes the row. Verify uses it to tell
--     "changed by Wingman after import" apart from "import error".

CREATE TABLE IF NOT EXISTS app_state (
  key         TEXT PRIMARY KEY,
  value       JSONB,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS qa_users (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email            TEXT NOT NULL UNIQUE,
  name             TEXT NOT NULL DEFAULT '',
  role             TEXT NOT NULL DEFAULT 'view',
  active           BOOLEAN NOT NULL DEFAULT TRUE,
  assign_audits    BOOLEAN NOT NULL DEFAULT TRUE,
  exclude_tickets  BOOLEAN NOT NULL DEFAULT FALSE,
  notes            TEXT NOT NULL DEFAULT '',
  archived         BOOLEAN NOT NULL DEFAULT FALSE,
  notion_page_id   TEXT UNIQUE,
  notion_raw       JSONB,
  imported_at      TIMESTAMPTZ,
  app_updated_at   TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Audits (one row per audit; a re-audit is a new row, the old one soft-deleted) ──
CREATE TABLE IF NOT EXISTS tickets (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id           TEXT NOT NULL DEFAULT '',
  agent_name          TEXT NOT NULL DEFAULT '',
  auditor             TEXT NOT NULL DEFAULT '',
  week                TEXT NOT NULL DEFAULT '',
  created_date        TEXT NOT NULL DEFAULT '',
  contact_reason      TEXT NOT NULL DEFAULT '',
  subject             TEXT NOT NULL DEFAULT '',
  ticket_url          TEXT NOT NULL DEFAULT '',
  ai_score            DOUBLE PRECISION,
  final_score         DOUBLE PRECISION,
  ai_passed           BOOLEAN NOT NULL DEFAULT FALSE,
  final_passed        BOOLEAN NOT NULL DEFAULT FALSE,
  has_disputes        BOOLEAN NOT NULL DEFAULT FALSE,
  reviewed            BOOLEAN NOT NULL DEFAULT FALSE,
  reviewed_by         TEXT NOT NULL DEFAULT '',
  reviewed_at         TEXT NOT NULL DEFAULT '',
  reviewer_notes      TEXT NOT NULL DEFAULT '',
  autofail            BOOLEAN NOT NULL DEFAULT FALSE,
  autofail_manual     BOOLEAN NOT NULL DEFAULT FALSE,
  scores              JSONB NOT NULL DEFAULT '{}'::jsonb,
  disputes            JSONB NOT NULL DEFAULT '{}'::jsonb,
  justifications      JSONB NOT NULL DEFAULT '{}'::jsonb,   -- full, untruncated
  autofails           JSONB NOT NULL DEFAULT '[]'::jsonb,
  notes_history       JSONB NOT NULL DEFAULT '{}'::jsonb,
  reopen_history      JSONB NOT NULL DEFAULT '[]'::jsonb,
  reaudit_history     JSONB NOT NULL DEFAULT '[]'::jsonb,
  -- Per-category notes: legacy/readable copies. On import they hold Notion's raw text;
  -- on every Wingman write they are regenerated from `justifications`.
  ctf_notes           TEXT NOT NULL DEFAULT '',
  empathy_notes       TEXT NOT NULL DEFAULT '',
  fcr_notes           TEXT NOT NULL DEFAULT '',
  product_notes       TEXT NOT NULL DEFAULT '',
  order_notes         TEXT NOT NULL DEFAULT '',
  returns_notes       TEXT NOT NULL DEFAULT '',
  promo_notes         TEXT NOT NULL DEFAULT '',
  retention_notes     TEXT NOT NULL DEFAULT '',
  comments            TEXT NOT NULL DEFAULT '',
  transcript          TEXT NOT NULL DEFAULT '',
  saved_at            TEXT NOT NULL DEFAULT '',
  audit_type          TEXT NOT NULL DEFAULT '',
  message_count       INTEGER,
  agent_message_count INTEGER,
  deleted             BOOLEAN NOT NULL DEFAULT FALSE,
  deleted_by          TEXT NOT NULL DEFAULT '',
  deleted_at          TEXT NOT NULL DEFAULT '',
  delete_reason       TEXT NOT NULL DEFAULT '',
  unlocked_override   BOOLEAN NOT NULL DEFAULT FALSE,
  unlocked_by         TEXT NOT NULL DEFAULT '',
  unlocked_at         TEXT NOT NULL DEFAULT '',
  unlock_reason       TEXT NOT NULL DEFAULT '',
  -- New in v3 (never stored in Notion)
  audit_week          TEXT NOT NULL DEFAULT '',
  total_points        DOUBLE PRECISION,
  max_points          DOUBLE PRECISION,
  replaced_for        TEXT NOT NULL DEFAULT '',
  customer_email      TEXT NOT NULL DEFAULT '',
  ai_meta             JSONB,          -- {product, ticketResolution} returned by the AI
  ctf_as_scored       JSONB,          -- CTF tag values exactly as shown to the AI
  matrix_version      INTEGER,        -- config_history version of 'matrix' used to score
  snapshot_status     TEXT NOT NULL DEFAULT 'none',  -- none|pending|ok|failed|not_found|skipped
  snapshot_attempts   INTEGER NOT NULL DEFAULT 0,
  snapshot_error      TEXT NOT NULL DEFAULT '',
  -- Import bookkeeping
  notion_page_id      TEXT UNIQUE,
  notion_raw          JSONB,
  imported_at         TIMESTAMPTZ,
  app_updated_at      TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tickets_deleted_saved_idx ON tickets (deleted, saved_at DESC);
CREATE INDEX IF NOT EXISTS tickets_ticket_id_idx     ON tickets (ticket_id);
CREATE INDEX IF NOT EXISTS tickets_agent_idx         ON tickets (agent_name);
CREATE INDEX IF NOT EXISTS tickets_week_idx          ON tickets (week);
CREATE INDEX IF NOT EXISTS tickets_snapshot_idx      ON tickets (snapshot_status);

-- ── Full Gorgias pull (GET /api/tickets/{id}) captured per audit ──────────────
-- Kept out of `tickets` so the startup ticket load never drags ~300 KB per row along.
CREATE TABLE IF NOT EXISTS ticket_snapshots (
  id                        BIGSERIAL PRIMARY KEY,
  audit_id                  UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  gorgias_ticket_id         BIGINT,
  fetched_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  raw                       JSONB NOT NULL,   -- full response; `requester` dropped when identical to `customer`
  status                    TEXT,
  channel                   TEXT,
  via                       TEXT,
  priority                  TEXT,
  language                  TEXT,
  assignee_user_id          BIGINT,
  assignee_email            TEXT,
  assignee_name             TEXT,
  assignee_team_id          BIGINT,
  tags                      TEXT[],
  custom_fields             JSONB,            -- {field_id: value}
  cf_contact_reason         TEXT,             -- 9969
  cf_product                TEXT,             -- 5807
  cf_ticket_resolution      TEXT,             -- 11375
  cf_additional_resolution  TEXT,             -- 11421
  cf_7630                   TEXT,             -- 7630 "AI Intent" (not read by the scorer)
  created_datetime          TIMESTAMPTZ,
  opened_datetime           TIMESTAMPTZ,
  closed_datetime           TIMESTAMPTZ,
  last_message_datetime     TIMESTAMPTZ,
  message_count             INTEGER,
  customer_id               BIGINT
);
CREATE INDEX IF NOT EXISTS ticket_snapshots_audit_idx   ON ticket_snapshots (audit_id);
CREATE INDEX IF NOT EXISTS ticket_snapshots_gorgias_idx ON ticket_snapshots (gorgias_ticket_id);

-- ── Config (matrix, autofails, scoringContext, calibrationBaseline, ...) ──────
-- One JSONB value per key: no chunking, no size cap. Every change is versioned.
CREATE TABLE IF NOT EXISTS config (
  key         TEXT PRIMARY KEY,
  value       JSONB,
  version     INTEGER NOT NULL DEFAULT 1,
  updated_by  TEXT NOT NULL DEFAULT '',
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  notion_raw  JSONB
);
CREATE TABLE IF NOT EXISTS config_history (
  id        BIGSERIAL PRIMARY KEY,
  key       TEXT NOT NULL,
  version   INTEGER NOT NULL,
  value     JSONB,
  saved_by  TEXT NOT NULL DEFAULT '',
  saved_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  source    TEXT NOT NULL DEFAULT 'app',   -- app | import
  UNIQUE (key, version)
);

-- ── Agent reports (HTML) ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_email     TEXT NOT NULL DEFAULT '',
  agent_name      TEXT NOT NULL DEFAULT '',
  week            TEXT NOT NULL DEFAULT '',
  generated_at    TEXT NOT NULL DEFAULT '',
  generated_by    TEXT NOT NULL DEFAULT '',
  content         TEXT NOT NULL DEFAULT '',   -- full HTML, no 20 x 1990 cap
  notion_page_id  TEXT UNIQUE,
  notion_raw      JSONB,
  imported_at     TIMESTAMPTZ,
  app_updated_at  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reports_email_week_idx ON reports (lower(agent_email), week);

-- ── Team Calibration ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS calib_rounds (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  week                   TEXT NOT NULL DEFAULT '',
  status                 TEXT NOT NULL DEFAULT '',
  participants           JSONB NOT NULL DEFAULT '[]'::jsonb,
  pool                   JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at_text        TEXT NOT NULL DEFAULT '',
  created_by             TEXT NOT NULL DEFAULT '',
  insights_generated_at  TEXT NOT NULL DEFAULT '',
  insights               JSONB,
  notion_page_id         TEXT UNIQUE,
  notion_raw             JSONB,
  imported_at            TIMESTAMPTZ,
  app_updated_at         TIMESTAMPTZ,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS calib_rounds_week_idx ON calib_rounds (week);

CREATE TABLE IF NOT EXISTS calib_reviews (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  assignment_id   TEXT NOT NULL DEFAULT '',
  week            TEXT NOT NULL DEFAULT '',
  ticket_id       TEXT NOT NULL DEFAULT '',
  reviewer_email  TEXT NOT NULL DEFAULT '',
  reviewer_name   TEXT NOT NULL DEFAULT '',
  status          TEXT NOT NULL DEFAULT '',
  scores          JSONB NOT NULL DEFAULT '{}'::jsonb,
  notes           JSONB NOT NULL DEFAULT '{}'::jsonb,
  autofail        BOOLEAN NOT NULL DEFAULT FALSE,
  submitted_at    TEXT NOT NULL DEFAULT '',
  notion_page_id  TEXT UNIQUE,
  notion_raw      JSONB,
  imported_at     TIMESTAMPTZ,
  app_updated_at  TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS calib_reviews_week_idx ON calib_reviews (week, lower(reviewer_email));

-- ── Import / verify run log ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_runs (
  id           BIGSERIAL PRIMARY KEY,
  kind         TEXT NOT NULL,            -- import | verify
  started_by   TEXT NOT NULL DEFAULT '',
  started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at  TIMESTAMPTZ,
  status       TEXT NOT NULL DEFAULT 'running',   -- running | done | failed
  passed       BOOLEAN,
  summary      JSONB,
  detail       JSONB
);

-- ── Saved AI insights from the Home dashboard (v3.4.0) ──────────────────────
CREATE TABLE IF NOT EXISTS insights (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by   TEXT NOT NULL DEFAULT '',
  date_from    TEXT NOT NULL DEFAULT '',   -- dashboard filter (ticket date), '' = no bound
  date_to      TEXT NOT NULL DEFAULT '',
  audit_count  INTEGER NOT NULL DEFAULT 0,
  matrix_version INTEGER,
  content      JSONB NOT NULL,              -- {wentWell:[{headline,detail}], improve:[{headline,detail}]}
  stats        JSONB                        -- the aggregate numbers the AI was given (for audit/export)
);
CREATE INDEX IF NOT EXISTS insights_created_idx ON insights (created_at DESC);
