CREATE TABLE fixture_accounts(id VARBINARY(64) PRIMARY KEY, enabled TINYINT NOT NULL CHECK(enabled IN (0,1)));
SELECT GET_LOCK(CONCAT(DATABASE(),':fixture-ddl-barrier'),30);
SELECT RELEASE_LOCK(CONCAT(DATABASE(),':fixture-ddl-barrier'));
CREATE TABLE fixture_items(id VARBINARY(64) PRIMARY KEY,account_id VARBINARY(64) NOT NULL,payload JSON NOT NULL,FOREIGN KEY(account_id) REFERENCES fixture_accounts(id) ON DELETE CASCADE);
INSERT INTO fixture_accounts VALUES('seed',1);
