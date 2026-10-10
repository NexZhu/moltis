-- @base
CREATE TABLE connector_accounts (
 id VARBINARY(128) PRIMARY KEY,
 kind VARCHAR(64) NOT NULL,
 name TEXT NOT NULL,
 config JSON NOT NULL,
 enabled TINYINT NOT NULL CHECK (enabled IN (0,1)),
 created_at BIGINT NOT NULL,
 updated_at BIGINT NOT NULL,
 source_key VARBINARY(512),
 UNIQUE INDEX idx_connector_accounts_kind_source_key(kind, source_key)
);
CREATE TABLE connector_datasets (
 id VARBINARY(128) PRIMARY KEY,
 account_id VARBINARY(128) NOT NULL,
 name TEXT NOT NULL,
 config JSON NOT NULL,
 schedule_minutes BIGINT CHECK (schedule_minutes IS NULL OR schedule_minutes > 0),
 projection_jsonl TINYINT NOT NULL DEFAULT 0 CHECK (projection_jsonl IN (0,1)),
 projection_md TINYINT NOT NULL DEFAULT 0 CHECK (projection_md IN (0,1)),
 enabled TINYINT NOT NULL CHECK (enabled IN (0,1)),
 last_sync_at BIGINT,
 next_sync_at BIGINT,
 last_error TEXT,
 item_count BIGINT NOT NULL DEFAULT 0 CHECK (item_count >= 0),
 created_at BIGINT NOT NULL,
 updated_at BIGINT NOT NULL,
 instruction TEXT,
 plan_revision BIGINT NOT NULL DEFAULT 1,
 synced_plan_revision BIGINT,
 FOREIGN KEY(account_id) REFERENCES connector_accounts(id) ON DELETE CASCADE,
 INDEX idx_connector_datasets_account(account_id,updated_at DESC),
 INDEX idx_connector_datasets_due(enabled,next_sync_at)
);
CREATE TABLE connector_items (
 id VARBINARY(128) PRIMARY KEY,
 dataset_id VARBINARY(128) NOT NULL,
 remote_id VARBINARY(512) NOT NULL,
 kind VARCHAR(64) NOT NULL,
 remote_version TEXT,
 occurred_at TEXT,
 updated_at TEXT,
 body_json JSON NOT NULL,
 content_hash VARBINARY(128) NOT NULL,
 created_at BIGINT NOT NULL,
 stored_at BIGINT NOT NULL,
 deleted_at BIGINT,
 search_text TEXT NOT NULL,
 FOREIGN KEY(dataset_id) REFERENCES connector_datasets(id) ON DELETE CASCADE,
 UNIQUE INDEX idx_connector_items_dataset_remote(dataset_id,remote_id),
 INDEX idx_connector_items_dataset_active(dataset_id,deleted_at,occurred_at(128))
);
CREATE TABLE connector_sync_runs (
 id VARBINARY(128) PRIMARY KEY,
 dataset_id VARBINARY(128) NOT NULL,
 status VARCHAR(16) NOT NULL CHECK(status IN ('running','succeeded','failed')),
 started_at BIGINT NOT NULL,
 finished_at BIGINT,
 upserted BIGINT NOT NULL DEFAULT 0 CHECK(upserted >= 0),
 deleted BIGINT NOT NULL DEFAULT 0 CHECK(deleted >= 0),
 active BIGINT NOT NULL DEFAULT 0 CHECK(active >= 0),
 error TEXT,
 running_dataset_id VARBINARY(128) GENERATED ALWAYS AS (CASE WHEN status='running' THEN dataset_id ELSE NULL END) STORED,
 FOREIGN KEY(dataset_id) REFERENCES connector_datasets(id) ON DELETE CASCADE,
 INDEX idx_connector_sync_runs_recent(dataset_id,started_at DESC),
 UNIQUE INDEX idx_connector_sync_runs_one_running(running_dataset_id)
);
CREATE TABLE connector_source_states (
 dataset_id VARBINARY(128) NOT NULL,
 remote_id VARBINARY(512) NOT NULL,
 remote_version TEXT,
 disposition VARCHAR(16) NOT NULL CHECK(disposition IN ('included','filtered')),
 filter_reason TEXT,
 evaluated_plan_revision BIGINT NOT NULL CHECK(evaluated_plan_revision > 0),
 last_seen_run_id VARBINARY(128) NOT NULL,
 observed_at BIGINT NOT NULL,
 PRIMARY KEY(dataset_id,remote_id),
 FOREIGN KEY(dataset_id) REFERENCES connector_datasets(id) ON DELETE CASCADE,
 INDEX idx_connector_source_states_run(dataset_id,last_seen_run_id,disposition)
);
-- @direct_index
CREATE FULLTEXT INDEX connector_text ON connector_items(search_text) WITH PARSER {{parser}};
-- @fallback
CREATE TABLE connector_items_search (
 item_id VARBINARY(128) NOT NULL,
 dataset_id VARBINARY(128) NOT NULL,
 account_id VARBINARY(128) NOT NULL,
 search_text TEXT NOT NULL,
 deleted_at BIGINT,
 UNIQUE INDEX connector_pointer(item_id),
 INDEX connector_scope(account_id,dataset_id),
 FULLTEXT INDEX connector_text(search_text) WITH PARSER {{parser}}
) ORGANIZATION HEAP;
-- @direct_query
SELECT item.*, MATCH(item.search_text) AGAINST(? IN BOOLEAN MODE) AS __score
FROM connector_items AS item
JOIN connector_datasets AS dataset ON dataset.id=item.dataset_id
JOIN connector_accounts AS account ON account.id=dataset.account_id
WHERE account.id=? AND dataset.id=? AND (?=1 OR item.deleted_at IS NULL)
AND MATCH(item.search_text) AGAINST(? IN BOOLEAN MODE)>0
ORDER BY __score DESC,item.id ASC LIMIT ? OFFSET ?;
-- @fallback_query
SELECT item.*, MATCH(search.search_text) AGAINST(? IN BOOLEAN MODE) AS __score
FROM connector_items_search AS search
JOIN connector_items AS item ON item.id=search.item_id
JOIN connector_datasets AS dataset ON dataset.id=item.dataset_id AND dataset.id=search.dataset_id
JOIN connector_accounts AS account ON account.id=dataset.account_id AND account.id=search.account_id
WHERE account.id=? AND dataset.id=? AND (?=1 OR (item.deleted_at IS NULL AND search.deleted_at IS NULL))
AND MATCH(search.search_text) AGAINST(? IN BOOLEAN MODE)>0
ORDER BY __score DESC,item.id ASC LIMIT ? OFFSET ?;
-- @direct_list
SELECT item.* FROM connector_items AS item
JOIN connector_datasets AS dataset ON dataset.id=item.dataset_id
JOIN connector_accounts AS account ON account.id=dataset.account_id
WHERE account.id=? AND dataset.id=? AND (?=1 OR item.deleted_at IS NULL)
ORDER BY item.occurred_at DESC,item.remote_id ASC LIMIT ? OFFSET ?;
