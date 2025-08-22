/* ============================================================
   Full Environment + User Enumeration (Read-Only)
   Works on SQL Server & Azure SQL Managed Instance
   Safe / Non-destructive
   ============================================================ */

SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;
PRINT '=== START: ' + CONVERT(varchar(19), SYSDATETIME(), 120) + ' ===';

DECLARE @me sysname       = SUSER_NAME();
DECLARE @me_sid varbinary(85) = SUSER_SID();
DECLARE @nl  nchar(1) = CHAR(10);

PRINT '--- [0] CONTEXT / VERSION ---------------------------------------';
SELECT
    CurrentLogin        = SUSER_NAME(),
    OriginalLogin       = ORIGINAL_LOGIN(),
    LoginSID            = SUSER_SID(),
    ServerName          = @@SERVERNAME,
    Version             = @@VERSION,
    Edition             = CAST(SERVERPROPERTY('Edition')        AS sql_variant),
    EngineEdition       = CAST(SERVERPROPERTY('EngineEdition')  AS sql_variant), -- 8 = MI
    ProductLevel        = CAST(SERVERPROPERTY('ProductLevel')   AS sql_variant),
    ProductUpdateLevel  = CAST(SERVERPROPERTY('ProductUpdateLevel') AS sql_variant),
    Collation           = CAST(SERVERPROPERTY('Collation')      AS sql_variant);

PRINT '--- [1] SERVER PRINCIPALS / ROLES / PERMISSIONS ------------------';
-- Logins
SELECT name, type_desc, is_disabled, create_date, modify_date
FROM sys.server_principals
WHERE type IN ('S','U','G','X','E') -- SQL, Windows, Group, External, External Group
ORDER BY type_desc, name;

-- Server role memberships (who is sysadmin, etc.)
SELECT r.name AS server_role, m.name AS member_name, m.type_desc AS member_type, m.is_disabled
FROM sys.server_role_members srm
JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
JOIN sys.server_principals m ON srm.member_principal_id = m.principal_id
ORDER BY r.name, m.name;

-- Your server roles
SELECT r.name AS my_server_roles
FROM sys.server_role_members srm
JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
JOIN sys.server_principals m ON srm.member_principal_id = m.principal_id
WHERE m.name = @me;

-- Server-level explicit permissions for you
SELECT perm.state_desc, perm.permission_name, perm.class_desc, perm.major_id, perm.minor_id
FROM sys.server_permissions AS perm
JOIN sys.server_principals  AS prin ON perm.grantee_principal_id = prin.principal_id
WHERE prin.name = @me
ORDER BY perm.permission_name;

-- Impersonation grants (who can impersonate whom)
SELECT pr_grantee.name AS grantee, pe.state_desc, pe.permission_name, pr_target.name AS target_login
FROM sys.server_permissions pe
JOIN sys.server_principals pr_grantee ON pe.grantee_principal_id = pr_grantee.principal_id
LEFT JOIN sys.server_principals pr_target ON pe.major_id = pr_target.principal_id
WHERE pe.permission_name = 'IMPERSONATE'
ORDER BY grantee, target_login;

PRINT '--- [2] SERVER CONFIG FLAGS (RISKY FEATURES) ---------------------';
SELECT name, value_in_use
FROM sys.configurations
WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled','Ad Hoc Distributed Queries','show advanced options')
ORDER BY name;

PRINT '--- [3] DATABASES: INVENTORY / OWNERSHIP / STATE -----------------';
SELECT 
    d.database_id,
    d.name AS database_name,
    owner_name = SUSER_SNAME(d.owner_sid),
    d.state_desc,
    d.is_read_only,
    d.is_encrypted,        -- TDE
    d.containment_desc,
    d.compatibility_level,
    d.create_date,
    d.source_database_id,  -- not null => snapshot
    is_snapshot = CASE WHEN d.source_database_id IS NOT NULL THEN 1 ELSE 0 END
FROM sys.databases AS d
ORDER BY d.database_id;

PRINT '--- [4] LINKED SERVERS & SECURITY --------------------------------';
SELECT * FROM sys.servers WHERE is_linked = 1;
SELECT srv.name AS linked_server, ll.remote_name, ll.uses_self_credential, ll.modify_date
FROM sys.servers srv
LEFT JOIN sys.linked_logins ll ON srv.server_id = ll.server_id
WHERE srv.is_linked = 1
ORDER BY srv.name;

PRINT '--- [5] SQL AGENT: JOBS / STEPS / SCHEDULES / HISTORY -------------';
-- Jobs (MI/SQL Server with Agent)
IF DB_ID('msdb') IS NOT NULL
BEGIN
    USE msdb;

    SELECT j.job_id, j.name, j.enabled, owner_sid = j.owner_sid,
           owner_name = SUSER_SNAME(j.owner_sid),
           date_created = j.date_created, date_modified = j.date_modified
    FROM dbo.sysjobs AS j
    ORDER BY j.enabled DESC, j.name;

    SELECT j.name AS job_name, s.step_id, s.step_name, s.subsystem, s.command, s.database_name, s.proxy_id
    FROM dbo.sysjobsteps s
    JOIN dbo.sysjobs    j ON s.job_id = j.job_id
    ORDER BY j.name, s.step_id;

    SELECT j.name AS job_name, sch.schedule_id, sch.name AS schedule_name, sch.enabled, js.next_run_date, js.next_run_time
    FROM dbo.sysjobs j
    JOIN dbo.sysjobschedules js ON j.job_id = js.job_id
    JOIN dbo.sysschedules sch ON js.schedule_id = sch.schedule_id
    ORDER BY j.name;

    -- Job history (last 200 entries)
    SELECT TOP (200)
        j.name AS job_name,
        h.step_id, h.step_name, h.sql_message_id, h.sql_severity, h.message,
        run_date = CONVERT(varchar(10), h.run_date),
        run_time = RIGHT('000000' + CONVERT(varchar(6), h.run_time), 6),
        run_duration = h.run_duration,
        run_status = CASE h.run_status WHEN 0 THEN 'Failed' WHEN 1 THEN 'Succeeded' WHEN 2 THEN 'Retry' WHEN 3 THEN 'Canceled' ELSE 'Unknown' END
    FROM dbo.sysjobhistory h
    JOIN dbo.sysjobs j ON h.job_id = j.job_id
    ORDER BY h.instance_id DESC;

    -- Proxies & Credentials used by Agent
    SELECT p.proxy_id, p.name AS proxy_name, p.credential_id, c.name AS credential_name
    FROM dbo.sysproxies p
    LEFT JOIN master.sys.credentials c ON p.credential_id = c.credential_id;

    USE master;
END

PRINT '--- [6] BACKUP HISTORY (msdb) ------------------------------------';
IF DB_ID('msdb') IS NOT NULL
BEGIN
    USE msdb;

    -- Last backup per database by type (D=Full, I=Diff, L=Log)
    WITH last_b AS (
        SELECT 
            bs.database_name,
            bs.type,
            last_finish = MAX(bs.backup_finish_date)
        FROM dbo.backupset bs
        GROUP BY bs.database_name, bs.type
    )
    SELECT lb.database_name,
           last_full_backup = MAX(CASE WHEN lb.type='D' THEN lb.last_finish END),
           last_diff_backup = MAX(CASE WHEN lb.type='I' THEN lb.last_finish END),
           last_log_backup  = MAX(CASE WHEN lb.type='L' THEN lb.last_finish END)
    FROM last_b lb
    GROUP BY lb.database_name
    ORDER BY lb.database_name;

    -- Backup files/locations (media family)
    SELECT TOP (500)
        bs.database_name, bs.backup_start_date, bs.backup_finish_date,
        bs.type, bmf.physical_device_name, bs.backup_size
    FROM dbo.backupset bs
    JOIN dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
    ORDER BY bs.backup_finish_date DESC;

    -- Restore history (if any)
    IF OBJECT_ID('dbo.restorehistory') IS NOT NULL
        SELECT TOP (200) * FROM dbo.restorehistory ORDER BY restore_date DESC;

    USE master;
END

PRINT '--- [7] DATABASE-SCOPED: ROLES / PERMS / ORPHANED USERS (ALL DBs) -';

DECLARE @db sysname;
DECLARE dbs CURSOR FAST_FORWARD FOR
    SELECT name FROM sys.databases WHERE state = 0; -- online only

CREATE TABLE #DbRoleMap (
    database_name sysname,
    principal_name sysname,
    principal_type nvarchar(60),
    db_role sysname
);

CREATE TABLE #DbPerms (
    database_name sysname,
    db_user sysname,
    permission_name sysname,
    state_desc nvarchar(60),
    object_name sysname,
    object_type nvarchar(60)
);

CREATE TABLE #Orphans (
    database_name sysname,
    user_name sysname,
    type_desc nvarchar(60),
    auth_type nvarchar(60),
    sid varbinary(85),
    note nvarchar(200)
);

OPEN dbs;
FETCH NEXT FROM dbs INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @sql nvarchar(max) = N'
    USE ' + QUOTENAME(@db) + N';

    -- role membership for current user (if mapped)
    INSERT INTO #DbRoleMap(database_name, principal_name, principal_type, db_role)
    SELECT DB_NAME(), dp.name, dp.type_desc, drp.name
    FROM sys.database_principals dp
    LEFT JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
    LEFT JOIN sys.database_principals drp  ON drm.role_principal_id = drp.principal_id
    WHERE dp.sid = SUSER_SID() AND dp.name = USER_NAME();

    -- explicit permissions for current user
    INSERT INTO #DbPerms(database_name, db_user, permission_name, state_desc, object_name, object_type)
    SELECT DB_NAME(), prin.name, perm.permission_name, perm.state_desc, obj.name, obj.type_desc
    FROM sys.database_permissions perm
    JOIN sys.database_principals prin ON perm.grantee_principal_id = prin.principal_id
    LEFT JOIN sys.objects obj ON perm.major_id = obj.object_id
    WHERE prin.sid = SUSER_SID() AND prin.name = USER_NAME();

    -- orphaned users (no matching server principal SID) - informational
    INSERT INTO #Orphans(database_name, user_name, type_desc, auth_type, sid, note)
    SELECT DB_NAME(), dp.name, dp.type_desc, dp.authentication_type_desc, dp.sid,
           CASE WHEN dp.sid IS NULL THEN ''NULL SID''
                WHEN dp.sid NOT IN (SELECT sid FROM master.sys.server_principals WHERE sid IS NOT NULL)
                THEN ''No matching login on server''
                ELSE NULL END
    FROM sys.database_principals dp
    WHERE dp.type IN (''S'',''U'',''G'')      -- SQL, Windows, Group
      AND dp.sid IS NOT NULL
      AND dp.name NOT IN (''dbo'',''guest'',''INFORMATION_SCHEMA'',''sys'');';

    BEGIN TRY
        EXEC sp_executesql @sql;
    END TRY
    BEGIN CATCH
        PRINT 'Skipping DB ' + @db + ' due to: ' + ERROR_MESSAGE();
    END CATCH;

    FETCH NEXT FROM dbs INTO @db;
END
CLOSE dbs; DEALLOCATE dbs;

-- Results
SELECT * FROM #DbRoleMap ORDER BY database_name, principal_name, db_role;
SELECT * FROM #DbPerms ORDER BY database_name, permission_name, object_name;
SELECT * FROM #Orphans WHERE note IS NOT NULL ORDER BY database_name, user_name;

PRINT '--- [8] SNAPSHOTS / TEMPORAL / CDC / CHANGE TRACKING (ALL DBs) ----';

CREATE TABLE #Temporal(
    database_name sysname, schema_name sysname, table_name sysname, temporal_type_desc nvarchar(60), history_table sysname
);
CREATE TABLE #CDC(
    database_name sysname, tracked_table sysname
);
CREATE TABLE #CT(
    database_name sysname, change_tracking_enabled bit, retention_days int, auto_cleanup bit
);

DECLARE dbs2 CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
OPEN dbs2;
FETCH NEXT FROM dbs2 INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @sql2 nvarchar(max) = N'
    USE ' + QUOTENAME(@db) + N';

    -- Temporal tables
    INSERT INTO #Temporal(database_name, schema_name, table_name, temporal_type_desc, history_table)
    SELECT DB_NAME(), s.name, t.name, t.temporal_type_desc,
           CASE WHEN t.temporal_type > 0 THEN (SELECT QUOTENAME(SCHEMA_NAME(schema_id))+''.''+QUOTENAME(name) FROM sys.tables WHERE object_id = t.history_table_id) END
    FROM sys.tables t
    JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE t.temporal_type > 0;

    -- CDC
    IF EXISTS (SELECT 1 FROM sys.objects WHERE name = ''cdc'')
    BEGIN
        IF EXISTS (SELECT 1 FROM sys.schemas WHERE name = ''cdc'')
        BEGIN
            INSERT INTO #CDC(database_name, tracked_table)
            SELECT DB_NAME(), t.name
            FROM sys.tables t
            WHERE t.is_tracked_by_cdc = 1;
        END
    END

    -- Change Tracking (db-scoped)
    IF OBJECT_ID(''sys.change_tracking_databases'') IS NOT NULL
    BEGIN
        INSERT INTO #CT(database_name, change_tracking_enabled, retention_days, auto_cleanup)
        SELECT DB_NAME(), 1, retention_period, is_auto_cleanup_on
        FROM sys.change_tracking_databases
        WHERE database_id = DB_ID();
    END
    ELSE
    BEGIN
        INSERT INTO #CT(database_name, change_tracking_enabled, retention_days, auto_cleanup)
        SELECT DB_NAME(), 0, NULL, NULL;
    END
    ';
    BEGIN TRY
        EXEC sp_executesql @sql2;
    END TRY
    BEGIN CATCH
        PRINT 'Temporal/CDC/CT scan skipped for DB ' + @db + ' due to: ' + ERROR_MESSAGE();
    END CATCH;

    FETCH NEXT FROM dbs2 INTO @db;
END
CLOSE dbs2; DEALLOCATE dbs2;

SELECT * FROM #Temporal ORDER BY database_name, schema_name, table_name;
SELECT * FROM #CDC ORDER BY database_name, tracked_table;
SELECT * FROM #CT ORDER BY database_name;

PRINT '--- [9] AUDITING & EXTENDED EVENTS -------------------------------';
-- Server audits (SQL Server / MI)
IF OBJECT_ID('sys.server_audits') IS NOT NULL
    SELECT * FROM sys.server_audits;
IF OBJECT_ID('sys.server_audit_specifications') IS NOT NULL
    SELECT * FROM sys.server_audit_specifications;

-- Database audits (per-db)
DECLARE dbs3 CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
OPEN dbs3;
FETCH NEXT FROM dbs3 INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @sql3 nvarchar(max) = N'
    USE ' + QUOTENAME(@db) + N';
    IF OBJECT_ID(''sys.database_audit_specifications'') IS NOT NULL
        SELECT DB_NAME() AS database_name, * FROM sys.database_audit_specifications;';
    BEGIN TRY
        EXEC sp_executesql @sql3;
    END TRY
    BEGIN CATCH
        PRINT 'Audit scan skipped for DB ' + @db + ' due to: ' + ERROR_MESSAGE();
    END CATCH;
    FETCH NEXT FROM dbs3 INTO @db;
END
CLOSE dbs3; DEALLOCATE dbs3;

-- Extended Events (definitions + running sessions)
SELECT name, CAST(ISNULL(event_retention_mode,0) AS int) AS event_retention_mode, startup_state
FROM sys.server_event_sessions;
IF OBJECT_ID('sys.dm_xe_sessions') IS NOT NULL
    SELECT * FROM sys.dm_xe_sessions;

PRINT '--- [10] CREDENTIALS / DB-SCOPED CREDENTIALS / EXTERNAL SOURCES ---';
SELECT credential_id, name, identity_name, create_date
FROM sys.credentials
ORDER BY name;

DECLARE dbs4 CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
OPEN dbs4;
FETCH NEXT FROM dbs4 INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @sql4 nvarchar(max) = N'
    USE ' + QUOTENAME(@db) + N';
    IF OBJECT_ID(''sys.database_scoped_credentials'') IS NOT NULL
        SELECT DB_NAME() AS database_name, name, identity_name, create_date
        FROM sys.database_scoped_credentials;

    IF OBJECT_ID(''sys.external_data_sources'') IS NOT NULL
        SELECT DB_NAME() AS database_name, name, type, location, pushdown
        FROM sys.external_data_sources;
    ';
    BEGIN TRY
        EXEC sp_executesql @sql4;
    END TRY
    BEGIN CATCH
        PRINT 'Cred/EDS scan skipped for DB ' + @db + ' due to: ' + ERROR_MESSAGE();
    END CATCH;

    FETCH NEXT FROM dbs4 INTO @db;
END
CLOSE dbs4; DEALLOCATE dbs4;

PRINT '--- [11] MODULES WITH ELEVATION PATTERNS (EXECUTE AS / XP / OLE) --';

DECLARE dbs5 CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
OPEN dbs5;
FETCH NEXT FROM dbs5 INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @sql5 nvarchar(max) = N'
    USE ' + QUOTENAME(@db) + N';
    -- EXECUTE AS
    SELECT DB_NAME() AS database_name, OBJECT_SCHEMA_NAME(object_id) AS schema_name,
           OBJECT_NAME(object_id) AS object_name, definition
    FROM sys.sql_modules
    WHERE definition LIKE ''%EXECUTE AS%''

    -- Risky calls
    UNION ALL
    SELECT DB_NAME(), OBJECT_SCHEMA_NAME(object_id), OBJECT_NAME(object_id), definition
    FROM sys.sql_modules
    WHERE definition LIKE ''%xp_cmdshell%'' OR definition LIKE ''%sp_OACreate%''
       OR definition LIKE ''%OPENROWSET%'' OR definition LIKE ''%OPENDATASOURCE%''
       OR definition LIKE ''%xp_regread%'' OR definition LIKE ''%bcp %'';
    ';
    BEGIN TRY
        EXEC sp_executesql @sql5;
    END TRY
    BEGIN CATCH
        PRINT 'Module scan skipped for DB ' + @db + ' due to: ' + ERROR_MESSAGE();
    END CATCH;

    FETCH NEXT FROM dbs5 INTO @db;
END
CLOSE dbs5; DEALLOCATE dbs5;

PRINT '--- [12] YOUR EFFECTIVE PERMISSIONS SNAPSHOT ---------------------';
-- Server level
SELECT 'SERVER' AS scope_name, * FROM fn_my_permissions(NULL, 'SERVER');

-- Per database
DECLARE dbs6 CURSOR FAST_FORWARD FOR SELECT name FROM sys.databases WHERE state = 0;
OPEN dbs6;
FETCH NEXT FROM dbs6 INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    DECLARE @sql6 nvarchar(max) = N'
    USE ' + QUOTENAME(@db) + N';
    SELECT DB_NAME() AS database_name, * FROM fn_my_permissions(NULL, ''DATABASE'');';
    BEGIN TRY
        EXEC sp_executesql @sql6;
    END TRY
    BEGIN CATCH
        PRINT 'fn_my_permissions skipped for DB ' + @db + ' due to: ' + ERROR_MESSAGE();
    END CATCH;

    FETCH NEXT FROM dbs6 INTO @db;
END
CLOSE dbs6; DEALLOCATE dbs6;

PRINT '--- [13] OPTIONAL: OBJECT-LEVEL SAMPLE (TABLES YOU CAN SELECT) ----';
-- Uncomment and replace YourDB if you want a quick object test for your current user
-- USE YourDB;
-- SELECT o.schema_id, s.name AS schema_name, o.name AS object_name, o.type_desc
-- FROM sys.objects o JOIN sys.schemas s ON o.schema_id = s.schema_id
-- WHERE HAS_PERMS_BY_NAME(QUOTENAME(s.name)+''.''+QUOTENAME(o.name), ''OBJECT'', ''SELECT'') = 1
-- ORDER BY s.name, o.name;

PRINT '=== END: ' + CONVERT(varchar(19), SYSDATETIME(), 120) + ' ===';
