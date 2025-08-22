/* ================================================================
   FULL PENTEST ENUMERATION (READ-ONLY) -- Paste into SSMS / GUI
   Non-destructive. Uses TRY/CATCH to skip inaccessible items.
   Purpose: collect everything a pentester needs to triage DB attack surface.
   ================================================================ */

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;

PRINT '===== ENUMERATION START: ' + CONVERT(varchar(19), SYSDATETIME(), 120) + ' =====';

/* ---------------------------
   CONTEXT / BASIC INFO
   --------------------------- */
PRINT '--- CONTEXT / SESSION INFO ---';
BEGIN TRY
    SELECT
        CurrentLogin      = SUSER_NAME(),
        CurrentSID        = SUSER_SID(),
        CurrentLoginID    = SUSER_ID(),
        OriginalLogin     = ORIGINAL_LOGIN(),
        SessionUser       = SESSION_USER,
        SystemUser        = SYSTEM_USER,
        ServerName        = @@SERVERNAME,
        Version           = @@VERSION,
        EngineEdition     = CAST(SERVERPROPERTY('EngineEdition') AS sql_variant),
        Edition           = CAST(SERVERPROPERTY('Edition') AS sql_variant),
        ProductLevel      = CAST(SERVERPROPERTY('ProductLevel') AS sql_variant),
        Collation         = CAST(SERVERPROPERTY('Collation') AS sql_variant),
        IsClustered       = CAST(SERVERPROPERTY('IsClustered') AS sql_variant);
END TRY
BEGIN CATCH
    PRINT 'Context Info: skipped due to: ' + ERROR_MESSAGE();
END CATCH;


/* ---------------------------
   SERVER PRINCIPALS & ROLES
   --------------------------- */
PRINT '--- SERVER PRINCIPALS / ROLES ---';
BEGIN TRY
    SELECT name, principal_id, type, type_desc, is_fixed_role, is_disabled, create_date, modify_date
    FROM sys.server_principals
    ORDER BY type_desc, name;
END TRY BEGIN CATCH
    PRINT 'server_principals: skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    SELECT r.name AS role_name, m.name AS member_name, m.type_desc AS member_type, m.is_disabled
    FROM sys.server_role_members srm
    JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
    JOIN sys.server_principals m ON srm.member_principal_id = m.principal_id
    ORDER BY r.name, m.name;
END TRY BEGIN CATCH
    PRINT 'server_role_members: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* Check server roles membership for current login */
BEGIN TRY
    SELECT SUSER_NAME() AS current_login, r.name AS server_role
    FROM sys.server_role_members srm
    JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
    JOIN sys.server_principals m ON srm.member_principal_id = m.principal_id
    WHERE m.name = SUSER_NAME();
END TRY BEGIN CATCH
    PRINT 'my server roles: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   SERVER-LEVEL PERMISSIONS & IMPERSONATION
   --------------------------- */
PRINT '--- SERVER-LEVEL PERMISSIONS ---';
BEGIN TRY
    SELECT prin.name AS grantee, perm.permission_name, perm.state_desc, perm.class_desc, perm.major_id
    FROM sys.server_permissions perm
    JOIN sys.server_principals prin ON perm.grantee_principal_id = prin.principal_id
    ORDER BY prin.name, perm.permission_name;
END TRY BEGIN CATCH
    PRINT 'server_permissions: skipped - ' + ERROR_MESSAGE();
END CATCH;

PRINT '--- SERVER-IMPERSONATE MAPPINGS ---';
BEGIN TRY
    SELECT pr_grantee.name AS grantee, pe.state_desc AS state, pe.permission_name, pr_target.name AS target_login
    FROM sys.server_permissions pe
    JOIN sys.server_principals pr_grantee ON pe.grantee_principal_id = pr_grantee.principal_id
    LEFT JOIN sys.server_principals pr_target ON pe.major_id = pr_target.principal_id
    WHERE pe.permission_name = 'IMPERSONATE'
    ORDER BY pr_grantee.name, pr_target.name;
END TRY BEGIN CATCH
    PRINT 'server impersonate: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   SERVER CONFIGURATION & FEATURES
   --------------------------- */
PRINT '--- SERVER CONFIG & RISKY FEATURES ---';
BEGIN TRY
    SELECT name, value, value_in_use, minimum, maximum, [description]
    FROM sys.configurations
    WHERE name IN (
      'xp_cmdshell','clr enabled','Ole Automation Procedures',
      'Ad Hoc Distributed Queries','show advanced options',
      'contained database authentication','remote access'
    )
    ORDER BY name;
END TRY BEGIN CATCH
    PRINT 'sys.configurations: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* Endpoints (network surfaces) */
PRINT '--- ENDPOINTS ---';
BEGIN TRY
    SELECT name, type_desc, protocol_desc, state_desc, is_admin_endpoint
    FROM sys.endpoints;
END TRY BEGIN CATCH
    PRINT 'endpoints: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* Linked servers */
PRINT '--- LINKED SERVERS ---';
BEGIN TRY
    SELECT server_id, name, product, provider, data_source, is_linked, collation_name
    FROM sys.servers;
END TRY BEGIN CATCH
    PRINT 'linked servers: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   DATABASES / OWNERSHIP / SNAPSHOTS / TDE
   --------------------------- */
PRINT '--- DATABASES / OWNERSHIP / SNAPSHOT / TDE ---';
BEGIN TRY
    SELECT database_id, name AS database_name,
           SUSER_SNAME(owner_sid) AS owner_name,
           state_desc, is_read_only, is_auto_close_on,
           is_encrypted, containment_desc, recovery_model_desc,
           source_database_id, create_date, compatibility_level
    FROM sys.databases
    ORDER BY database_id;
END TRY BEGIN CATCH
    PRINT 'sys.databases: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* Database snapshot check */
PRINT '--- DATABASE SNAPSHOTS ---';
BEGIN TRY
    SELECT name AS snapshot_name, database_id, source_database_id, create_date
    FROM sys.databases
    WHERE source_database_id IS NOT NULL;
END TRY BEGIN CATCH
    PRINT 'snapshots: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   MSDB / AGENT / JOBS / PROXIES / OPERATORS
   --------------------------- */
PRINT '--- MSDB: Jobs / Steps / Proxies / History (if accessible) ---';
BEGIN TRY
    IF DB_ID('msdb') IS NOT NULL
    BEGIN
        USE msdb;
        SELECT job_id, name AS job_name, enabled, description, date_created, date_modified, owner_sid, SUSER_SNAME(owner_sid) AS owner_name
        FROM dbo.sysjobs
        ORDER BY enabled DESC, name;

        SELECT j.name AS job_name, s.step_id, s.step_name, s.subsystem, s.command, s.database_name, s.server
        FROM dbo.sysjobsteps s
        JOIN dbo.sysjobs j ON s.job_id = j.job_id
        ORDER BY j.name, s.step_id;

        SELECT TOP(200) j.name AS job_name, h.run_date, h.run_time, h.run_duration, 
            CASE h.run_status WHEN 0 THEN 'Failed' WHEN 1 THEN 'Succeeded' WHEN 2 THEN 'Retry' WHEN 3 THEN 'Canceled' ELSE 'Unknown' END AS run_status,
            h.message
        FROM dbo.sysjobhistory h
        JOIN dbo.sysjobs j ON h.job_id = j.job_id
        ORDER BY h.instance_id DESC;

        SELECT proxy_id, name AS proxy_name, credential_id, credential_name = ISNULL((SELECT name FROM master.sys.credentials c WHERE c.credential_id = p.credential_id), '(n/a)')
        FROM dbo.sysproxies p;
        
        SELECT name, email_address, enabled FROM dbo.sysoperators;
        USE master;
    END
    ELSE
        PRINT 'msdb not present or not accessible';
END TRY BEGIN CATCH
    PRINT 'msdb job enumeration skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   BACKUPS / RESTORES / MEDIA
   --------------------------- */
PRINT '--- BACKUP HISTORY (msdb) ---';
BEGIN TRY
    IF DB_ID('msdb') IS NOT NULL
    BEGIN
        USE msdb;
        SELECT TOP(500)
            bs.database_name, bs.type AS backup_type, bs.backup_start_date, bs.backup_finish_date,
            bmf.physical_device_name, bs.backup_size, bs.server_name, bs.user_name
        FROM dbo.backupset bs
        JOIN dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
        ORDER BY bs.backup_finish_date DESC;
        USE master;
    END
    ELSE
        PRINT 'backup history: msdb missing';
END TRY BEGIN CATCH
    PRINT 'backup history skipped - ' + ERROR_MESSAGE();
END CATCH;

/* Restore history (if present) */
PRINT '--- RESTORE HISTORY (msdb.restorehistory) ---';
BEGIN TRY
    IF DB_ID('msdb') IS NOT NULL AND OBJECT_ID('msdb.dbo.restorehistory') IS NOT NULL
    BEGIN
        USE msdb;
        SELECT TOP(200) * FROM dbo.restorehistory ORDER BY restore_date DESC;
        USE master;
    END
END TRY BEGIN CATCH
    PRINT 'restore history skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   CREDENTIALS / DATABASE-SCOPED CREDENTIALS / EXTERNAL DATA SOURCES
   --------------------------- */
PRINT '--- CREDENTIALS & DB-SCOPED CREDENTIALS / EXTERNAL DATA SOURCES ---';
BEGIN TRY
    SELECT credential_id, name, credential_identity = principal_id, create_date FROM sys.credentials;
END TRY BEGIN CATCH
    PRINT 'sys.credentials skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    DECLARE @dbname sysname;
    DECLARE dbc CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN dbc;
    FETCH NEXT FROM dbc INTO @dbname;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql nvarchar(max) = N'USE ' + QUOTENAME(@dbname) + N';
                IF OBJECT_ID(''sys.database_scoped_credentials'') IS NOT NULL
                    SELECT DB_NAME() AS db, name, credential_identity, create_date FROM sys.database_scoped_credentials;
                IF OBJECT_ID(''sys.external_data_sources'') IS NOT NULL
                    SELECT DB_NAME() AS db, name, type, location, pushdown FROM sys.external_data_sources;';
            EXEC sp_executesql @sql;
        END TRY BEGIN CATCH
            PRINT 'db-scoped creds/external for ' + @dbname + ' skipped - ' + ERROR_MESSAGE();
        END CATCH;

        FETCH NEXT FROM dbc INTO @dbname;
    END
    CLOSE dbc; DEALLOCATE dbc;
END TRY BEGIN CATCH
    PRINT 'db-scoped credential enumeration skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   TEMPORAL / CDC / CHANGE TRACKING
   --------------------------- */
PRINT '--- TEMPORAL TABLES / CDC / CHANGE TRACKING ---';
BEGIN TRY
    DECLARE @db2 sysname;
    DECLARE cdc_cur CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cdc_cur;
    FETCH NEXT FROM cdc_cur INTO @db2;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql2 nvarchar(max) = N'USE ' + QUOTENAME(@db2) + N';
                -- Temporal tables
                SELECT DB_NAME() AS database_name, s.name AS schema_name, t.name AS table_name, t.temporal_type_desc, h.name AS history_table
                FROM sys.tables t
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                LEFT JOIN sys.tables h ON t.history_table_id = h.object_id
                WHERE t.temporal_type > 0;
                -- CDC tracked tables
                IF OBJECT_ID(''cdc.change_tables'') IS NOT NULL
                BEGIN
                    SELECT DB_NAME() AS database_name, OBJECT_SCHEMA_NAME(ct.object_id) AS schema_name, OBJECT_NAME(ct.object_id) AS tracked_table
                    FROM cdc.change_tables ct;
                END
                -- Change tracking DB-level info
                IF OBJECT_ID(''sys.change_tracking_databases'') IS NOT NULL
                BEGIN
                    SELECT DB_NAME() AS database_name, retention_period, is_auto_cleanup_on FROM sys.change_tracking_databases WHERE database_id = DB_ID();
                END';
            EXEC sp_executesql @sql2;
        END TRY BEGIN CATCH
            PRINT 'Temporal/CDC/CT scan skipped for ' + @db2 + ' - ' + ERROR_MESSAGE();
        END CATCH;

        FETCH NEXT FROM cdc_cur INTO @db2;
    END
    CLOSE cdc_cur; DEALLOCATE cdc_cur;
END TRY BEGIN CATCH
    PRINT 'Temporal/CDC scanning: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   MODULES/PRECOMPILED CODE: PROCEDURES, EXECUTE AS, ASSEMBLIES, CLR, XPs
   --------------------------- */
PRINT '--- MODULES: EXECUTE AS / xp_cmdshell / sp_OACreate / OPENROWSET patterns ---';
BEGIN TRY
    DECLARE @db3 sysname;
    DECLARE modcur CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN modcur;
    FETCH NEXT FROM modcur INTO @db3;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @m sql_variant = @db3;
            DECLARE @sql3 nvarchar(max) = N'USE ' + QUOTENAME(@db3) + N';
                SELECT DB_NAME() AS db, OBJECT_SCHEMA_NAME(object_id) AS schema_name, OBJECT_NAME(object_id) AS object_name, definition
                FROM sys.sql_modules
                WHERE definition LIKE ''%EXECUTE AS%'' OR definition LIKE ''%EXECUTE AS OWNER%'' OR definition LIKE ''%EXECUTE AS ''%''

                UNION ALL

                SELECT DB_NAME(), OBJECT_SCHEMA_NAME(object_id), OBJECT_NAME(object_id), definition
                FROM sys.sql_modules
                WHERE definition LIKE ''%xp_cmdshell%'' OR definition LIKE ''%sp_OACreate%'' OR definition LIKE ''%OPENROWSET%'' OR definition LIKE ''%OPENDATASOURCE%'' OR definition LIKE ''%xp_regread%'' OR definition LIKE ''%bcp %'';';
            EXEC sp_executesql @sql3;
        END TRY BEGIN CATCH
            PRINT 'Module scan skipped for ' + @db3 + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM modcur INTO @db3;
    END
    CLOSE modcur; DEALLOCATE modcur;
END TRY BEGIN CATCH
    PRINT 'modules enumeration skipped - ' + ERROR_MESSAGE();
END CATCH;

/* CLR / Assemblies */
PRINT '--- CLR / Assemblies (DB & Server) ---';
BEGIN TRY
    SELECT * FROM sys.assemblies;
END TRY BEGIN CATCH
    PRINT 'sys.assemblies (server) skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    DECLARE @db4 sysname;
    DECLARE asmcur CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN asmcur;
    FETCH NEXT FROM asmcur INTO @db4;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            EXEC('USE ' + QUOTENAME(@db4) + '; SELECT DB_NAME() AS db, assembly_id, name, permission_set_desc FROM sys.assemblies;');
        END TRY BEGIN CATCH
            PRINT 'assemblies skipped for ' + @db4 + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM asmcur INTO @db4;
    END
    CLOSE asmcur; DEALLOCATE asmcur;
END TRY BEGIN CATCH
    PRINT 'assemblies (per-db) skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   OBJECT-LEVEL PERMISSIONS / WHAT YOU CAN DO
   --------------------------- */
PRINT '--- OBJECT-LEVEL PERMISSIONS FOR CURRENT USER (fn_my_permissions) ---';
BEGIN TRY
    SELECT 'SERVER' AS scope, * FROM fn_my_permissions(NULL, 'SERVER');
END TRY BEGIN CATCH
    PRINT 'fn_my_permissions SERVER: skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    DECLARE @db5 sysname;
    DECLARE permcur CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN permcur;
    FETCH NEXT FROM permcur INTO @db5;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            EXEC('USE ' + QUOTENAME(@db5) + ';
                  SELECT DB_NAME() AS database_name, * FROM fn_my_permissions(NULL, ''DATABASE'');');
        END TRY BEGIN CATCH
            PRINT 'fn_my_permissions skipped for ' + @db5 + ' - ' + ERROR_MESSAGE();
        END CATCH;

        FETCH NEXT FROM permcur INTO @db5;
    END
    CLOSE permcur; DEALLOCATE permcur;
END TRY BEGIN CATCH
    PRINT 'fn_my_permissions (per-db): skipped - ' + ERROR_MESSAGE();
END CATCH;

/* Explicit grants/denies for your mapped user across DBs */
PRINT '--- EXPLICIT DB PERMISSIONS FOR CURRENT MAPPED USER ---';
BEGIN TRY
    DECLARE @db6 sysname;
    DECLARE perm2 CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN perm2;
    FETCH NEXT FROM perm2 INTO @db6;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            EXEC('USE ' + QUOTENAME(@db6) + ';
                SELECT DB_NAME() AS database_name, prin.name AS db_principal, perm.permission_name, perm.state_desc,
                       OBJECT_SCHEMA_NAME(perm.major_id) AS object_schema, OBJECT_NAME(perm.major_id) AS object_name
                FROM sys.database_permissions perm
                JOIN sys.database_principals prin ON perm.grantee_principal_id = prin.principal_id
                WHERE prin.sid = SUSER_SID() OR prin.name = USER_NAME();');
        END TRY BEGIN CATCH
            PRINT 'explicit db permissions skipped for ' + @db6 + ' - ' + ERROR_MESSAGE();
        END CATCH;

        FETCH NEXT FROM perm2 INTO @db6;
    END
    CLOSE perm2; DEALLOCATE perm2;
END TRY BEGIN CATCH
    PRINT 'explicit db perms (loop) skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   ORPHANED USERS / USER MAPPINGS
   --------------------------- */
PRINT '--- ORPHANED USERS & SID MISMATCHES ---';
BEGIN TRY
    DECLARE @db7 sysname;
    DECLARE orphan CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN orphan;
    FETCH NEXT FROM orphan INTO @db7;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            EXEC('USE ' + QUOTENAME(@db7) + ';
                SELECT DB_NAME() AS database_name, dp.name AS user_name, dp.type_desc, dp.authentication_type_desc, dp.sid,
                       CASE WHEN dp.sid IS NULL THEN ''NULL SID''
                            WHEN dp.sid NOT IN (SELECT sid FROM master.sys.server_principals WHERE sid IS NOT NULL) THEN ''No matching login on server''
                            ELSE NULL END AS note
                FROM sys.database_principals dp
                WHERE dp.type IN (''S'',''U'',''G'') AND dp.principal_id > 4;');
        END TRY BEGIN CATCH
            PRINT 'orphans skipped for ' + @db7 + ' - ' + ERROR_MESSAGE();
        END CATCH;

        FETCH NEXT FROM orphan INTO @db7;
    END
    CLOSE orphan; DEALLOCATE orphan;
END TRY BEGIN CATCH
    PRINT 'orphan scanning skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   AUDITING / EXTENDED EVENTS / POLICY-BASED MANAGEMENT
   --------------------------- */
PRINT '--- AUDITS / SERVER & DB AUDIT SPECIFICATIONS / XE SESSIONS ---';
BEGIN TRY
    IF OBJECT_ID('sys.server_audits') IS NOT NULL
        SELECT * FROM sys.server_audits;
END TRY BEGIN CATCH
    PRINT 'server_audits skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    IF OBJECT_ID('sys.server_audit_specifications') IS NOT NULL
        SELECT * FROM sys.server_audit_specifications;
END TRY BEGIN CATCH
    PRINT 'server_audit_specifications skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    IF OBJECT_ID('sys.database_audit_specifications') IS NOT NULL
    BEGIN
        DECLARE @db8 sysname;
        DECLARE aud CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
        OPEN aud;
        FETCH NEXT FROM aud INTO @db8;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            BEGIN TRY
                EXEC('USE ' + QUOTENAME(@db8) + ';
                      IF OBJECT_ID(''sys.database_audit_specifications'') IS NOT NULL
                          SELECT DB_NAME() AS database_name, * FROM sys.database_audit_specifications;');
            END TRY BEGIN CATCH
                PRINT 'db audit specs skipped for ' + @db8 + ' - ' + ERROR_MESSAGE();
            END CATCH;

            FETCH NEXT FROM aud INTO @db8;
        END
        CLOSE aud; DEALLOCATE aud;
    END
END TRY BEGIN CATCH
    PRINT 'database audit specification scanning skipped - ' + ERROR_MESSAGE();
END CATCH;

PRINT '--- EXTENDED EVENTS (server sessions) ---';
BEGIN TRY
    IF OBJECT_ID('sys.server_event_sessions') IS NOT NULL
        SELECT * FROM sys.server_event_sessions;
    IF OBJECT_ID('sys.dm_xe_sessions') IS NOT NULL
        SELECT * FROM sys.dm_xe_sessions;
END TRY BEGIN CATCH
    PRINT 'XE sessions: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   DMVs (informational) -- may require VIEW SERVER STATE
   --------------------------- */
PRINT '--- DMVs (connections, exec requests, open transactions) ---';
BEGIN TRY
    IF OBJECT_ID('sys.dm_exec_sessions') IS NOT NULL
    BEGIN
        SELECT TOP(50) session_id, login_name, host_name, program_name, status, last_request_end_time
        FROM sys.dm_exec_sessions
        ORDER BY last_request_end_time DESC;
    END
END TRY BEGIN CATCH
    PRINT 'dmv sessions skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    IF OBJECT_ID('sys.dm_exec_requests') IS NOT NULL
    BEGIN
        SELECT TOP(50) session_id, status, command, blocking_session_id, wait_type, cpu_time, total_elapsed_time
        FROM sys.dm_exec_requests
        ORDER BY total_elapsed_time DESC;
    END
END TRY BEGIN CATCH
    PRINT 'dmv requests skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   FILESYSTEM / FILES / FILESTREAM / FILETABLES
   --------------------------- */
PRINT '--- DATABASE FILES / FILESTREAM / FILETABLES ---';
BEGIN TRY
    SELECT DB_NAME(database_id) AS database_name, file_id, name, type_desc, physical_name, size/128.0 AS size_mb, max_size
    FROM sys.master_files
    ORDER BY database_id, file_id;
END TRY BEGIN CATCH
    PRINT 'master_files skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    DECLARE @db9 sysname;
    DECLARE fs CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN fs;
    FETCH NEXT FROM fs INTO @db9;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            EXEC('USE ' + QUOTENAME(@db9) + ';
                IF OBJECT_ID(''sys.filetables'') IS NOT NULL
                    SELECT DB_NAME() AS database_name, name, object_id FROM sys.filetables;');
        END TRY BEGIN CATCH
            PRINT 'filetable check skipped for ' + @db9 + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM fs INTO @db9;
    END
    CLOSE fs; DEALLOCATE fs;
END TRY BEGIN CATCH
    PRINT 'filetable scanning skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   KEY MATERIAL: CERTIFICATES / KEYS / ASYMMETRIC / SYMMETRIC
   --------------------------- */
PRINT '--- CERTIFICATES / KEYS / ASYMMETRIC KEYS ---';
BEGIN TRY
    SELECT * FROM sys.server_certificates;
END TRY BEGIN CATCH
    PRINT 'server_certificates skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    SELECT * FROM sys.certificates;
END TRY BEGIN CATCH
    PRINT 'certificates (db) skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    SELECT * FROM sys.asymmetric_keys;
END TRY BEGIN CATCH
    PRINT 'asymmetric_keys skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   MISC: DATABASE MAIL, POLICY, RESOURCE GOVERNOR
   --------------------------- */
PRINT '--- DATABASE MAIL / POLICY / RESOURCE GOVERNOR ---';
BEGIN TRY
    IF OBJECT_ID('msdb.dbo.sysmail_server') IS NOT NULL
    BEGIN
        SELECT name, email_address, account_id FROM msdb.dbo.sysmail_profile;
        SELECT * FROM msdb.dbo.sysmail_server;
    END
END TRY BEGIN CATCH
    PRINT 'database mail info skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    IF OBJECT_ID('sys.resource_governor_configuration') IS NOT NULL
        SELECT * FROM sys.resource_governor_configuration;
END TRY BEGIN CATCH
    PRINT 'resource governor skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   FINAL: SUMMARY OF FINDINGS / WHAT YOU ARE
   --------------------------- */
PRINT '--- QUICK SUMMARY: YOUR MAPPING & ROLES ---';
BEGIN TRY
    SELECT
        CurrentLogin = SUSER_NAME(),
        LoginSID = SUSER_SID(),
        LoginID = SUSER_ID(),
        MappedUser = USER_NAME(),
        DBsYouMapTo = (SELECT STRING_AGG(name, ',') FROM sys.databases d WHERE EXISTS (SELECT 1 FROM sys.database_principals dp WHERE dp.sid = SUSER_SID() AND DB_NAME() = d.name)),
        IsSysadmin = IS_SRVROLEMEMBER('sysadmin'),
        IsServerRoleMemberList = (SELECT STRING_AGG(r.name, ',') FROM sys.server_role_members srm JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id JOIN sys.server_principals m ON srm.member_principal_id = m.principal_id WHERE m.name = SUSER_NAME())
END TRY BEGIN CATCH
    PRINT 'quick summary skipped - ' + ERROR_MESSAGE();
END CATCH;

PRINT '===== ENUMERATION END: ' + CONVERT(varchar(19), SYSDATETIME(), 120) + ' =====';
