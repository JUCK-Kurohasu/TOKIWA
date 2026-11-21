-- schema created by create_all at commit f993282 (before the 2026-11 audit fixes)
CREATE TABLE actor_sessions (
	source_ip VARCHAR(64) NOT NULL, 
	client_fingerprint VARCHAR(64) NOT NULL, 
	user_agent TEXT, 
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	request_count INTEGER NOT NULL, 
	error_count INTEGER NOT NULL, 
	unique_paths INTEGER NOT NULL, 
	features JSON NOT NULL, 
	ai_score FLOAT NOT NULL, 
	classification VARCHAR(32) NOT NULL, 
	incident_id VARCHAR(64), 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE advisories (
	created_at DATETIME NOT NULL, 
	vuln_ids JSON NOT NULL, 
	title VARCHAR(512) NOT NULL, 
	priority VARCHAR(4) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	analysis JSON NOT NULL, 
	llm_call_id VARCHAR(64), 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE alerts (
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	count INTEGER NOT NULL, 
	fingerprint VARCHAR(128) NOT NULL, 
	rule_id VARCHAR(128) NOT NULL, 
	detector VARCHAR(128) NOT NULL, 
	title VARCHAR(512) NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	confidence FLOAT NOT NULL, 
	category VARCHAR(32) NOT NULL, 
	mitre JSON NOT NULL, 
	ai_score FLOAT, 
	source_ip VARCHAR(64), 
	entities JSON NOT NULL, 
	evidence_event_ids JSON NOT NULL, 
	tags JSON NOT NULL, 
	details JSON NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	incident_id VARCHAR(64), 
	triage JSON, 
	id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE api_tokens (
	name VARCHAR(64) NOT NULL, 
	token_hash VARCHAR(128) NOT NULL, 
	prefix VARCHAR(16) NOT NULL, 
	scopes JSON NOT NULL, 
	created_at DATETIME NOT NULL, 
	last_used DATETIME, 
	revoked BOOLEAN NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE assets (
	name VARCHAR(255) NOT NULL, 
	kind VARCHAR(32) NOT NULL, 
	hostname VARCHAR(255), 
	ips JSON NOT NULL, 
	software JSON NOT NULL, 
	criticality VARCHAR(16) NOT NULL, 
	owner VARCHAR(128), 
	tags JSON NOT NULL, 
	notes TEXT, 
	id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE audit_log (
	created_at DATETIME NOT NULL, 
	actor VARCHAR(128) NOT NULL, 
	action VARCHAR(128) NOT NULL, 
	target VARCHAR(256), 
	details JSON NOT NULL, 
	note TEXT, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE copilot_conversations (
	title VARCHAR(255) NOT NULL, 
	owner VARCHAR(64) NOT NULL, 
	context JSON NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE copilot_messages (
	conversation_id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	content TEXT NOT NULL, 
	blocks JSON NOT NULL, 
	llm_call_id VARCHAR(64), 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE deception_assets (
	kind VARCHAR(32) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	path TEXT, 
	token VARCHAR(255), 
	content_template TEXT, 
	description TEXT, 
	enabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	trip_count INTEGER NOT NULL, 
	last_tripped DATETIME, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE deception_trips (
	created_at DATETIME NOT NULL, 
	timestamp DATETIME NOT NULL, 
	asset_id VARCHAR(64) NOT NULL, 
	asset_kind VARCHAR(32) NOT NULL, 
	event_id VARCHAR(64) NOT NULL, 
	source_ip VARCHAR(64), 
	trip_type VARCHAR(32) NOT NULL, 
	ai_followed BOOLEAN NOT NULL, 
	detail JSON NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE events (
	id VARCHAR(64) NOT NULL, 
	timestamp DATETIME NOT NULL, 
	ingested_at DATETIME NOT NULL, 
	kind VARCHAR(32) NOT NULL, 
	dataset VARCHAR(64) NOT NULL, 
	sensor_id VARCHAR(128), 
	host_name VARCHAR(255), 
	source_ip VARCHAR(64), 
	source_port INTEGER, 
	dest_ip VARCHAR(64), 
	dest_port INTEGER, 
	http_method VARCHAR(16), 
	http_host VARCHAR(255), 
	http_path TEXT, 
	http_status INTEGER, 
	user_agent TEXT, 
	session_id VARCHAR(64), 
	asset_id VARCHAR(64), 
	tags JSON NOT NULL, 
	data JSON NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE host_ports (
	host VARCHAR(255) NOT NULL, 
	protocol VARCHAR(8) NOT NULL, 
	bind_ip VARCHAR(64) NOT NULL, 
	port INTEGER NOT NULL, 
	pid INTEGER, 
	process_name VARCHAR(255), 
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	open BOOLEAN NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE incidents (
	first_seen DATETIME NOT NULL, 
	last_seen DATETIME NOT NULL, 
	title VARCHAR(512) NOT NULL, 
	summary TEXT NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	category VARCHAR(32) NOT NULL, 
	actor_type VARCHAR(32) NOT NULL, 
	ai_score FLOAT, 
	source_ips JSON NOT NULL, 
	alert_count INTEGER NOT NULL, 
	kill_chain JSON NOT NULL, 
	mitre JSON NOT NULL, 
	triage JSON, 
	assignee VARCHAR(64), 
	tags JSON NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE intel_items (
	source VARCHAR(64) NOT NULL, 
	url TEXT, 
	url_hash VARCHAR(64), 
	title TEXT NOT NULL, 
	summary TEXT, 
	published DATETIME, 
	fetched_at DATETIME NOT NULL, 
	vuln_ids JSON NOT NULL, 
	tags JSON NOT NULL, 
	relevance FLOAT, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (url_hash)
);
CREATE TABLE llm_calls (
	created_at DATETIME NOT NULL, 
	provider VARCHAR(32) NOT NULL, 
	model VARCHAR(64) NOT NULL, 
	tier VARCHAR(16) NOT NULL, 
	purpose VARCHAR(32) NOT NULL, 
	prompt_version VARCHAR(64) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	input_tokens INTEGER NOT NULL, 
	output_tokens INTEGER NOT NULL, 
	cache_read_tokens INTEGER NOT NULL, 
	cache_write_tokens INTEGER NOT NULL, 
	web_search_requests INTEGER NOT NULL, 
	cost_usd FLOAT NOT NULL, 
	latency_ms FLOAT NOT NULL, 
	related JSON NOT NULL, 
	error TEXT, 
	request_redacted TEXT, 
	response_text TEXT, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE notification_channels (
	kind VARCHAR(16) NOT NULL, 
	name VARCHAR(128) NOT NULL, 
	config JSON NOT NULL, 
	min_severity VARCHAR(16) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE port_baselines (
	host VARCHAR(255) NOT NULL, 
	protocol VARCHAR(8) NOT NULL, 
	port INTEGER NOT NULL, 
	process_name VARCHAR(255), 
	allow_public BOOLEAN NOT NULL, 
	note TEXT, 
	created_at DATETIME NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE research_reports (
	created_at DATETIME NOT NULL, 
	topic TEXT NOT NULL, 
	output JSON NOT NULL, 
	citations JSON NOT NULL, 
	llm_call_id VARCHAR(64), 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE response_actions (
	action_type VARCHAR(32) NOT NULL, 
	target VARCHAR(255) NOT NULL, 
	params JSON NOT NULL, 
	reason TEXT NOT NULL, 
	proposed_by VARCHAR(16) NOT NULL, 
	incident_id VARCHAR(64), 
	alert_id VARCHAR(64), 
	status VARCHAR(16) NOT NULL, 
	reversible BOOLEAN NOT NULL, 
	ttl_minutes INTEGER, 
	approved_by VARCHAR(64), 
	approved_at DATETIME, 
	executed_at DATETIME, 
	expires_at DATETIME, 
	reverted_at DATETIME, 
	result JSON NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE rules (
	kind VARCHAR(16) NOT NULL, 
	title VARCHAR(512) NOT NULL, 
	content TEXT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	source VARCHAR(16) NOT NULL, 
	hit_count INTEGER NOT NULL, 
	meta JSON NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE settings_kv (
	"key" VARCHAR(128) NOT NULL, 
	value JSON NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY ("key")
);
CREATE TABLE users (
	username VARCHAR(64) NOT NULL, 
	password_hash VARCHAR(512) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	created_at DATETIME NOT NULL, 
	last_login DATETIME, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE vuln_matches (
	vuln_id VARCHAR(64) NOT NULL, 
	asset_id VARCHAR(64) NOT NULL, 
	software JSON, 
	reason TEXT NOT NULL, 
	confidence FLOAT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	created_at DATETIME NOT NULL, 
	id VARCHAR(64) NOT NULL, 
	PRIMARY KEY (id)
);
CREATE TABLE vulns (
	id VARCHAR(64) NOT NULL, 
	aliases JSON NOT NULL, 
	sources JSON NOT NULL, 
	title TEXT, 
	description TEXT, 
	published DATETIME, 
	modified DATETIME, 
	cvss_score FLOAT, 
	cvss_vector VARCHAR(256), 
	severity VARCHAR(16), 
	epss FLOAT, 
	epss_percentile FLOAT, 
	kev BOOLEAN NOT NULL, 
	kev_date_added DATETIME, 
	kev_due_date DATETIME, 
	kev_ransomware BOOLEAN, 
	cwe JSON NOT NULL, 
	affected JSON NOT NULL, 
	"references" JSON NOT NULL, 
	data JSON NOT NULL, 
	updated_at DATETIME NOT NULL, 
	PRIMARY KEY (id)
);
CREATE INDEX ix_actor_sessions_ai_score ON actor_sessions (ai_score);
CREATE INDEX ix_actor_sessions_first_seen ON actor_sessions (first_seen);
CREATE INDEX ix_actor_sessions_last_seen ON actor_sessions (last_seen);
CREATE INDEX ix_actor_sessions_source_ip ON actor_sessions (source_ip);
CREATE INDEX ix_advisories_created_at ON advisories (created_at);
CREATE INDEX ix_advisories_priority ON advisories (priority);
CREATE INDEX ix_alerts_category ON alerts (category);
CREATE INDEX ix_alerts_created_at ON alerts (created_at);
CREATE INDEX ix_alerts_fingerprint ON alerts (fingerprint);
CREATE INDEX ix_alerts_incident_id ON alerts (incident_id);
CREATE INDEX ix_alerts_last_seen ON alerts (last_seen);
CREATE INDEX ix_alerts_rule_id ON alerts (rule_id);
CREATE INDEX ix_alerts_severity ON alerts (severity);
CREATE INDEX ix_alerts_source_ip ON alerts (source_ip);
CREATE INDEX ix_alerts_status ON alerts (status);
CREATE UNIQUE INDEX ix_api_tokens_token_hash ON api_tokens (token_hash);
CREATE INDEX ix_assets_created_at ON assets (created_at);
CREATE INDEX ix_assets_hostname ON assets (hostname);
CREATE INDEX ix_assets_name ON assets (name);
CREATE INDEX ix_audit_log_action ON audit_log (action);
CREATE INDEX ix_audit_log_created_at ON audit_log (created_at);
CREATE INDEX ix_copilot_conversations_created_at ON copilot_conversations (created_at);
CREATE INDEX ix_copilot_conversations_owner ON copilot_conversations (owner);
CREATE INDEX ix_copilot_messages_conversation_id ON copilot_messages (conversation_id);
CREATE INDEX ix_copilot_messages_created_at ON copilot_messages (created_at);
CREATE INDEX ix_deception_assets_kind ON deception_assets (kind);
CREATE INDEX ix_deception_assets_token ON deception_assets (token);
CREATE INDEX ix_deception_trips_asset_id ON deception_trips (asset_id);
CREATE INDEX ix_deception_trips_event_id ON deception_trips (event_id);
CREATE INDEX ix_deception_trips_source_ip ON deception_trips (source_ip);
CREATE INDEX ix_deception_trips_timestamp ON deception_trips (timestamp);
CREATE INDEX ix_events_dataset ON events (dataset);
CREATE INDEX ix_events_dest_port ON events (dest_port);
CREATE INDEX ix_events_host_name ON events (host_name);
CREATE INDEX ix_events_kind ON events (kind);
CREATE INDEX ix_events_session_id ON events (session_id);
CREATE INDEX ix_events_source_ip ON events (source_ip);
CREATE INDEX ix_events_source_ts ON events (source_ip, timestamp);
CREATE INDEX ix_events_timestamp ON events (timestamp);
CREATE INDEX ix_host_ports_host ON host_ports (host);
CREATE INDEX ix_incidents_created_at ON incidents (created_at);
CREATE INDEX ix_incidents_last_seen ON incidents (last_seen);
CREATE INDEX ix_incidents_severity ON incidents (severity);
CREATE INDEX ix_incidents_status ON incidents (status);
CREATE INDEX ix_intel_items_published ON intel_items (published);
CREATE INDEX ix_intel_items_source ON intel_items (source);
CREATE INDEX ix_llm_calls_created_at ON llm_calls (created_at);
CREATE INDEX ix_llm_calls_purpose ON llm_calls (purpose);
CREATE INDEX ix_llm_calls_status ON llm_calls (status);
CREATE INDEX ix_port_baselines_host ON port_baselines (host);
CREATE INDEX ix_research_reports_created_at ON research_reports (created_at);
CREATE INDEX ix_response_actions_action_type ON response_actions (action_type);
CREATE INDEX ix_response_actions_created_at ON response_actions (created_at);
CREATE INDEX ix_response_actions_expires_at ON response_actions (expires_at);
CREATE INDEX ix_response_actions_incident_id ON response_actions (incident_id);
CREATE INDEX ix_response_actions_status ON response_actions (status);
CREATE INDEX ix_response_actions_target ON response_actions (target);
CREATE INDEX ix_rules_created_at ON rules (created_at);
CREATE INDEX ix_rules_status ON rules (status);
CREATE UNIQUE INDEX ix_users_username ON users (username);
CREATE INDEX ix_vuln_matches_asset_id ON vuln_matches (asset_id);
CREATE INDEX ix_vuln_matches_status ON vuln_matches (status);
CREATE INDEX ix_vuln_matches_vuln_id ON vuln_matches (vuln_id);
CREATE INDEX ix_vulns_epss ON vulns (epss);
CREATE INDEX ix_vulns_kev ON vulns (kev);
CREATE INDEX ix_vulns_modified ON vulns (modified);
CREATE INDEX ix_vulns_published ON vulns (published);
