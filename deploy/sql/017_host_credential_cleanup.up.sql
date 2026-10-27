-- Cleanup includes revoked and expired credentials, so the existing partial
-- active index cannot constrain its reads to one installation.
create index host_connection_credentials_installation
    on host_connection_credentials (installation_id);
