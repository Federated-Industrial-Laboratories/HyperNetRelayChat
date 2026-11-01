// SPDX-License-Identifier: Apache-2.0
//! Authoritative feature schema. Storage owns encryption and continuity metadata.
pub(super) const SQL: &str = r#"
CREATE TABLE hrc_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL,home BLOB NOT NULL,signer BLOB NOT NULL,position INTEGER NOT NULL DEFAULT 0,clock_floor INTEGER NOT NULL DEFAULT 0,history_bytes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE hrc_invitations(id TEXT PRIMARY KEY,principal TEXT NOT NULL,class BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE hrc_accounts(id TEXT PRIMARY KEY,account BLOB NOT NULL,class BLOB NOT NULL,recovery BLOB NOT NULL,security INTEGER NOT NULL,revision INTEGER NOT NULL,nickname TEXT NOT NULL,lookup TEXT NOT NULL,filter_revision INTEGER NOT NULL DEFAULT 1);
CREATE INDEX hrc_account_lookup ON hrc_accounts(lookup);
CREATE TABLE hrc_endpoints(account TEXT NOT NULL,endpoint TEXT NOT NULL,actor BLOB NOT NULL,key BLOB NOT NULL,principal TEXT NOT NULL,disabled INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account,endpoint));
CREATE TABLE hrc_windows(id TEXT PRIMARY KEY,account TEXT NOT NULL,endpoint TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE INDEX hrc_window_account ON hrc_windows(account,endpoint,expires);
CREATE TABLE hrc_operations(window TEXT NOT NULL,operation TEXT NOT NULL,digest BLOB NOT NULL,action BLOB NOT NULL,outcome BLOB NOT NULL,created INTEGER NOT NULL,read_only INTEGER NOT NULL,PRIMARY KEY(window,operation));
CREATE INDEX hrc_operation_expiry ON hrc_operations(created);
CREATE TABLE hrc_rooms(id TEXT PRIMARY KEY,room BLOB NOT NULL,name TEXT NOT NULL,topic TEXT NOT NULL,owner TEXT NOT NULL,revision INTEGER NOT NULL,sequence INTEGER NOT NULL,created INTEGER NOT NULL,earliest INTEGER NOT NULL DEFAULT 1,mode INTEGER NOT NULL DEFAULT 0);
CREATE TABLE hrc_members(room TEXT NOT NULL,account TEXT NOT NULL,active INTEGER NOT NULL,revision INTEGER NOT NULL,history_from INTEGER NOT NULL,moderator INTEGER NOT NULL,PRIMARY KEY(room,account));
CREATE TABLE hrc_events(position INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,room TEXT NOT NULL,sequence INTEGER NOT NULL,created INTEGER NOT NULL,actor TEXT NOT NULL,represented TEXT NOT NULL,operator TEXT,kind INTEGER NOT NULL,event BLOB NOT NULL,text TEXT NOT NULL,normal TEXT NOT NULL,bytes INTEGER NOT NULL,causal_root TEXT,causal_depth INTEGER NOT NULL DEFAULT 0,UNIQUE(room,sequence));
CREATE INDEX hrc_event_room ON hrc_events(room,sequence);
CREATE INDEX hrc_event_expiry ON hrc_events(created);
CREATE VIRTUAL TABLE hrc_search USING fts5(normal,content='hrc_events',content_rowid='position',tokenize='trigram case_sensitive 1');
CREATE TRIGGER hrc_search_insert AFTER INSERT ON hrc_events BEGIN INSERT INTO hrc_search(rowid,normal) VALUES(new.position,new.normal); END;
CREATE TRIGGER hrc_search_delete AFTER DELETE ON hrc_events BEGIN INSERT INTO hrc_search(hrc_search,rowid,normal) VALUES('delete',old.position,old.normal); END;
CREATE TABLE hrc_grants(id TEXT PRIMARY KEY,owner TEXT NOT NULL,agent TEXT NOT NULL,endpoint TEXT NOT NULL,generation INTEGER NOT NULL,state INTEGER NOT NULL,grant_data BLOB NOT NULL);
CREATE TABLE hrc_approvals(id TEXT PRIMARY KEY,owner TEXT NOT NULL,grant_id TEXT NOT NULL,generation INTEGER NOT NULL,digest BLOB NOT NULL,action BLOB NOT NULL,expires INTEGER NOT NULL,state INTEGER NOT NULL);
CREATE INDEX hrc_approval_expiry ON hrc_approvals(expires);
CREATE TABLE hrc_filters(owner TEXT NOT NULL,subject TEXT NOT NULL,ignored INTEGER NOT NULL,muted INTEGER NOT NULL,PRIMARY KEY(owner,subject));
CREATE TABLE hrc_restrictions(room TEXT NOT NULL,subject TEXT NOT NULL,kind INTEGER NOT NULL,expires INTEGER NOT NULL,moderator TEXT NOT NULL,PRIMARY KEY(room,subject,kind));
CREATE TABLE hrc_unread(room TEXT NOT NULL,account TEXT NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(room,account));
CREATE TABLE hrc_presence(account TEXT NOT NULL,endpoint TEXT NOT NULL,status TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(account,endpoint));
CREATE TABLE hrc_budgets(key TEXT PRIMARY KEY,credit INTEGER NOT NULL,updated INTEGER NOT NULL);
CREATE TABLE hrc_agent_effects(cause TEXT NOT NULL,agent TEXT NOT NULL,grant_id TEXT NOT NULL,root TEXT NOT NULL,PRIMARY KEY(cause,agent,grant_id));
CREATE INDEX hrc_agent_root ON hrc_agent_effects(root);
"#;
