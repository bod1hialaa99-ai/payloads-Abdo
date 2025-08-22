/* ================================================================
   FIXED: Full Pentest Enumeration Script (SSMS / GUI friendly)
   Read-only. Avoids previous QUOTENAME quoting errors.
   Paste and run in SSMS as one batch.
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
        EngineEdition     = TRY_CAST(SERVERPROPERTY('EngineEdition') AS sql_variant),
        Edition           = TRY_CAST(SERVERPROPERTY('Edition') AS sql_variant),
        ProductLevel      = TRY_CAST(SERVERPROPERTY('ProductLevel') AS sql_variant),
        Collation         = TRY_CAST(SERVERPROPERTY('Collation') AS sql_variant),
        IsClustered       = TRY_CAST(SERVERPROPERTY('IsClustered') AS sql_variant);
END TRY
BEGIN CATCH
    PRINT 'Context Info: skipped due to: ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   SERVER PRINCIPALS & ROLES
   --------------------------- */
PRINT '--- SERVER PRINCIPALS / ROLES ---';
BEGIN TRY
    SELECT name, principal_id, type, type_desc, is_fixed_role, is_disabled, default_database_name, create_date, modify_date
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

/* current login's server roles (if any) */
BEGIN TRY
    SELECT DISTINCT r.name AS my_server_role
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

/* Endpoints */
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

        SELECT proxy_id, name AS proxy_name, credential_id,
               ISNULL((SELECT name FROM master.sys.credentials c WHERE c.credential_id = p.credential_id), '(n/a)') AS credential_name
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

/* ---------------------------
   DB-SCOPED CREDENTIALS / EXTERNAL DATA SOURCES
   --------------------------- */
PRINT '--- DB-SCOPED CREDENTIALS / EXTERNAL DATA SOURCES (per DB) ---';
BEGIN TRY
    DECLARE @db_for_creds sysname;
    DECLARE cur_creds CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_creds;
    FETCH NEXT FROM cur_creds INTO @db_for_creds;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_creds nvarchar(max) = N'USE ' + QUOTENAME(@db_for_creds) + N';
                IF OBJECT_ID(''sys.database_scoped_credentials'') IS NOT NULL
                    SELECT DB_NAME() AS database_name, name AS scoped_credential, credential_identity, create_date FROM sys.database_scoped_credentials;
                IF OBJECT_ID(''sys.external_data_sources'') IS NOT NULL
                    SELECT DB_NAME() AS database_name, name AS external_data_source, type, location, pushdown FROM sys.external_data_sources;';
            EXEC sp_executesql @sql_creds;
        END TRY BEGIN CATCH
            PRINT 'db-scoped creds/external for ' + @db_for_creds + ' skipped - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_creds INTO @db_for_creds;
    END
    CLOSE cur_creds; DEALLOCATE cur_creds;
END TRY BEGIN CATCH
    PRINT 'db-scoped credential enumeration skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   TEMPORAL / CDC / CHANGE TRACKING
   --------------------------- */
PRINT '--- TEMPORAL TABLES / CDC / CHANGE TRACKING ---';
BEGIN TRY
    DECLARE @db_ct sysname;
    DECLARE cur_ct CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_ct;
    FETCH NEXT FROM cur_ct INTO @db_ct;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_ct nvarchar(max) = N'USE ' + QUOTENAME(@db_ct) + N';
                SELECT DB_NAME() AS database_name, s.name AS schema_name, t.name AS table_name, t.temporal_type_desc, h.name AS history_table
                FROM sys.tables t
                JOIN sys.schemas s ON t.schema_id = s.schema_id
                LEFT JOIN sys.tables h ON t.history_table_id = h.object_id
                WHERE t.temporal_type > 0;
                IF OBJECT_ID(''cdc.change_tables'') IS NOT NULL
                BEGIN
                    SELECT DB_NAME() AS database_name, OBJECT_SCHEMA_NAME(ct.object_id) AS schema_name, OBJECT_NAME(ct.object_id) AS tracked_table
                    FROM cdc.change_tables ct;
                END
                IF OBJECT_ID(''sys.change_tracking_databases'') IS NOT NULL
                BEGIN
                    SELECT DB_NAME() AS database_name, retention_period, is_auto_cleanup_on FROM sys.change_tracking_databases WHERE database_id = DB_ID();
                END';
            EXEC sp_executesql @sql_ct;
        END TRY BEGIN CATCH
            PRINT 'Temporal/CDC/CT scan skipped for ' + @db_ct + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_ct INTO @db_ct;
    END
    CLOSE cur_ct; DEALLOCATE cur_ct;
END TRY BEGIN CATCH
    PRINT 'Temporal/CDC scanning: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   MODULES/PRECOMPILED CODE: PROCEDURES, EXECUTE AS, ASSEMBLIES, CLR, XPs
   --------------------------- */
PRINT '--- MODULES: EXECUTE AS / xp_cmdshell / sp_OACreate / OPENROWSET patterns ---';
BEGIN TRY
    DECLARE @db_mod sysname;
    DECLARE cur_mod CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_mod;
    FETCH NEXT FROM cur_mod INTO @db_mod;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_mod nvarchar(max) = N'USE ' + QUOTENAME(@db_mod) + N';
                SELECT DB_NAME() AS db, OBJECT_SCHEMA_NAME(object_id) AS schema_name, OBJECT_NAME(object_id) AS object_name, definition
                FROM sys.sql_modules
                WHERE definition LIKE ''%EXECUTE AS%'' OR definition LIKE ''%EXECUTE AS OWNER%'' OR definition LIKE ''%EXECUTE AS '''';

                UNION ALL

                SELECT DB_NAME(), OBJECT_SCHEMA_NAME(object_id), OBJECT_NAME(object_id), definition
                FROM sys.sql_modules
                WHERE definition LIKE ''%xp_cmdshell%'' OR definition LIKE ''%sp_OACreate%'' OR definition LIKE ''%OPENROWSET%'' OR definition LIKE ''%OPENDATASOURCE%'' OR definition LIKE ''%xp_regread%'' OR definition LIKE ''%bcp %'';';
            EXEC sp_executesql @sql_mod;
        END TRY BEGIN CATCH
            PRINT 'Module scan skipped for ' + @db_mod + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_mod INTO @db_mod;
    END
    CLOSE cur_mod; DEALLOCATE cur_mod;
END TRY BEGIN CATCH
    PRINT 'modules enumeration skipped - ' + ERROR_MESSAGE();
END CATCH;

/* CLR / Assemblies (server + per db) */
PRINT '--- CLR / ASSEMBLIES (server + per-db) ---';
BEGIN TRY
    SELECT * FROM sys.assemblies;
END TRY BEGIN CATCH
    PRINT 'sys.assemblies (server) skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    DECLARE @db_asm sysname;
    DECLARE cur_asm CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_asm;
    FETCH NEXT FROM cur_asm INTO @db_asm;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_asm nvarchar(max) = N'USE ' + QUOTENAME(@db_asm) + N'; SELECT DB_NAME() AS database_name, assembly_id, name, permission_set_desc FROM sys.assemblies;';
            EXEC sp_executesql @sql_asm;
        END TRY BEGIN CATCH
            PRINT 'assemblies skipped for ' + @db_asm + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_asm INTO @db_asm;
    END
    CLOSE cur_asm; DEALLOCATE cur_asm;
END TRY BEGIN CATCH
    PRINT 'assemblies (per-db) skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   OBJECT-LEVEL PERMISSIONS / fn_my_permissions
   --------------------------- */
PRINT '--- FN_MY_PERMISSIONS: SERVER ---';
BEGIN TRY
    SELECT 'SERVER' AS scope_name, * FROM fn_my_permissions(NULL, 'SERVER');
END TRY BEGIN CATCH
    PRINT 'fn_my_permissions SERVER: skipped - ' + ERROR_MESSAGE();
END CATCH;

PRINT '--- FN_MY_PERMISSIONS: PER DATABASE ---';
BEGIN TRY
    DECLARE @db_perm sysname;
    DECLARE cur_perm CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_perm;
    FETCH NEXT FROM cur_perm INTO @db_perm;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_perm nvarchar(max) = N'USE ' + QUOTENAME(@db_perm) + N'; SELECT DB_NAME() AS database_name, * FROM fn_my_permissions(NULL, ''DATABASE'');';
            EXEC sp_executesql @sql_perm;
        END TRY BEGIN CATCH
            PRINT 'fn_my_permissions skipped for ' + @db_perm + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_perm INTO @db_perm;
    END
    CLOSE cur_perm; DEALLOCATE cur_perm;
END TRY BEGIN CATCH
    PRINT 'fn_my_permissions (per-db) skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   EXPLICIT DB PERMISSIONS FOR YOUR MAPPED USER
   --------------------------- */
PRINT '--- EXPLICIT DB PERMISSIONS FOR CURRENT USER (per DB) ---';
BEGIN TRY
    DECLARE @db_perm2 sysname;
    DECLARE cur_perm2 CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_perm2;
    FETCH NEXT FROM cur_perm2 INTO @db_perm2;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_perm2 nvarchar(max) = N'USE ' + QUOTENAME(@db_perm2) + N';
                SELECT DB_NAME() AS database_name, prin.name AS db_principal, perm.permission_name, perm.state_desc,
                       OBJECT_SCHEMA_NAME(perm.major_id) AS object_schema, OBJECT_NAME(perm.major_id) AS object_name
                FROM sys.database_permissions perm
                JOIN sys.database_principals prin ON perm.grantee_principal_id = prin.principal_id
                WHERE prin.sid = SUSER_SID() OR prin.name = USER_NAME();';
            EXEC sp_executesql @sql_perm2;
        END TRY BEGIN CATCH
            PRINT 'explicit db permissions skipped for ' + @db_perm2 + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_perm2 INTO @db_perm2;
    END
    CLOSE cur_perm2; DEALLOCATE cur_perm2;
END TRY BEGIN CATCH
    PRINT 'explicit db perms (loop) skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   ORPHANED USERS / USER MAPPINGS
   --------------------------- */
PRINT '--- ORPHANED USERS & SID MISMATCHES (per DB) ---';
BEGIN TRY
    DECLARE @db_orph sysname;
    DECLARE cur_orph CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_orph;
    FETCH NEXT FROM cur_orph INTO @db_orph;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_orph nvarchar(max) = N'USE ' + QUOTENAME(@db_orph) + N';
                SELECT DB_NAME() AS database_name, dp.name AS user_name, dp.type_desc, dp.authentication_type_desc, dp.sid,
                       CASE WHEN dp.sid IS NULL THEN ''NULL SID''
                            WHEN dp.sid NOT IN (SELECT sid FROM master.sys.server_principals WHERE sid IS NOT NULL) THEN ''No matching login on server''
                            ELSE NULL END AS note
                FROM sys.database_principals dp
                WHERE dp.type IN (''S'',''U'',''G'') AND dp.principal_id > 4;';
            EXEC sp_executesql @sql_orph;
        END TRY BEGIN CATCH
            PRINT 'orphans skipped for ' + @db_orph + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_orph INTO @db_orph;
    END
    CLOSE cur_orph; DEALLOCATE cur_orph;
END TRY BEGIN CATCH
    PRINT 'orphan scanning skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   AUDITING / EXTENDED EVENTS
   --------------------------- */
PRINT '--- AUDITS / EXTENDED EVENTS ---';
BEGIN TRY
    IF OBJECT_ID('sys.server_audits') IS NOT NULL
        SELECT * FROM sys.server_audits;
END TRY BEGIN CATCH
    PRINT 'server_audits skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    IF OBJECT_ID('sys.server_event_sessions') IS NOT NULL
        SELECT * FROM sys.server_event_sessions;
    IF OBJECT_ID('sys.dm_xe_sessions') IS NOT NULL
        SELECT * FROM sys.dm_xe_sessions;
END TRY BEGIN CATCH
    PRINT 'XE sessions: skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   DMVs (informational)
   --------------------------- */
PRINT '--- DMVs: SESSIONS / REQUESTS (may be restricted) ---';
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
   FILES, FILESTREAM, FILETABLES
   --------------------------- */
PRINT '--- FILES / MASTER_FILES / FILETABLES ---';
BEGIN TRY
    SELECT DB_NAME(database_id) AS database_name, file_id, name, type_desc, physical_name, size/128.0 AS size_mb, max_size
    FROM sys.master_files
    ORDER BY database_id, file_id;
END TRY BEGIN CATCH
    PRINT 'master_files skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    DECLARE @db_ft sysname;
    DECLARE cur_ft CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
    OPEN cur_ft;
    FETCH NEXT FROM cur_ft INTO @db_ft;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            DECLARE @sql_ft nvarchar(max) = N'USE ' + QUOTENAME(@db_ft) + N';
                IF OBJECT_ID(''sys.filetables'') IS NOT NULL
                    SELECT DB_NAME() AS database_name, name, object_id FROM sys.filetables;';
            EXEC sp_executesql @sql_ft;
        END TRY BEGIN CATCH
            PRINT 'filetable check skipped for ' + @db_ft + ' - ' + ERROR_MESSAGE();
        END CATCH;
        FETCH NEXT FROM cur_ft INTO @db_ft;
    END
    CLOSE cur_ft; DEALLOCATE cur_ft;
END TRY BEGIN CATCH
    PRINT 'filetable scanning skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   KEYS / CERTIFICATES
   --------------------------- */
PRINT '--- CERTIFICATES / KEYS ---';
BEGIN TRY
    IF OBJECT_ID('sys.server_certificates') IS NOT NULL
        SELECT * FROM sys.server_certificates;
END TRY BEGIN CATCH
    PRINT 'server_certificates skipped - ' + ERROR_MESSAGE();
END CATCH;

BEGIN TRY
    IF OBJECT_ID('sys.certificates') IS NOT NULL
        SELECT * FROM sys.certificates;
END TRY BEGIN CATCH
    PRINT 'certificates (db) skipped - ' + ERROR_MESSAGE();
END CATCH;

/* ---------------------------
   FINAL: QUICK SUMMARY
   --------------------------- */
PRINT '--- QUICK SUMMARY ---';
BEGIN TRY
    SELECT
        CurrentLogin = SUSER_NAME(),
        LoginSID = SUSER_SID(),
        LoginID = SUSER_ID(),
        MappedUser = USER_NAME(),
        IsSysadmin = IS_SRVROLEMEMBER('sysadmin');
END TRY BEGIN CATCH
    PRINT 'quick summary skipped - ' + ERROR_MESSAGE();
END CATCH;

PRINT '===== ENUMERATION END: ' + CONVERT(varchar(19), SYSDATETIME(), 120) + ' =====';
