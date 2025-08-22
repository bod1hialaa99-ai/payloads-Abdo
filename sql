/* ========================================================
   SQL Server Full Enumeration Script (No cmd.exe needed)
   Works in SSMS GUI (removes identity_name references)
   ======================================================== */

-- Current login & session info
SELECT SUSER_NAME() AS CurrentLogin,
       SUSER_SID() AS LoginSID,
       ORIGINAL_LOGIN() AS OriginalLogin,
       SYSTEM_USER AS SystemUser,
       SESSION_USER AS SessionUser;

-- All logins
SELECT name, type_desc, is_disabled, default_database_name, create_date, modify_date
FROM sys.server_principals
WHERE type IN ('S','U','G') -- SQL, Windows, Groups
ORDER BY name;

-- Server roles and members
SELECT sp.name AS LoginName, spr.name AS RoleName
FROM sys.server_role_members srm
JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id
JOIN sys.server_principals spr ON srm.role_principal_id = spr.principal_id
ORDER BY sp.name;

-- Explicit server-level permissions
SELECT sp.name AS PrincipalName, perm.permission_name, perm.state_desc
FROM sys.server_permissions perm
JOIN sys.server_principals sp ON perm.grantee_principal_id = sp.principal_id
ORDER BY sp.name;

-- Databases visible to you
SELECT name AS DatabaseName, suser_sname(owner_sid) AS Owner, state_desc, create_date
FROM sys.databases
ORDER BY name;

-- Orphaned users in each database
EXEC sp_msforeachdb '
USE [?];
SELECT DB_NAME() AS DatabaseName, dp.name AS OrphanedUser
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE sp.sid IS NULL AND dp.type IN (''S'',''U'') AND dp.principal_id > 4;
';

-- Database roles and memberships
EXEC sp_msforeachdb '
USE [?];
SELECT DB_NAME() AS DatabaseName, dp.name AS UserName, drp.name AS RoleName
FROM sys.database_role_members drm
JOIN sys.database_principals dp ON drm.member_principal_id = dp.principal_id
JOIN sys.database_principals drp ON drm.role_principal_id = drp.principal_id;
';

-- Explicit database permissions
EXEC sp_msforeachdb '
USE [?];
SELECT DB_NAME() AS DatabaseName,
       prin.name AS PrincipalName,
       perm.permission_name,
       perm.state_desc,
       obj.name AS ObjectName,
       obj.type_desc
FROM sys.database_permissions perm
LEFT JOIN sys.objects obj ON perm.major_id = obj.object_id
JOIN sys.database_principals prin ON perm.grantee_principal_id = prin.principal_id;
';

-- SQL Agent Jobs (if accessible)
SELECT j.job_id, j.name AS JobName, j.enabled, s.srvname AS TargetServer
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobservers s ON j.job_id = s.job_id;

-- Job history
SELECT j.name AS JobName, h.run_date, h.run_time, h.run_status, h.message
FROM msdb.dbo.sysjobhistory h
JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id;

-- Backup history
SELECT d.name AS DatabaseName,
       b.backup_start_date,
       b.backup_finish_date,
       b.type AS BackupType,
       mf.physical_device_name
FROM msdb.dbo.backupset b
JOIN msdb.dbo.backupmediafamily mf ON b.media_set_id = mf.media_set_id
JOIN sys.databases d ON b.database_name = d.name
ORDER BY b.backup_finish_date DESC;

-- Snapshots (if any)
SELECT name AS SnapshotName, source_database_id, create_date
FROM sys.databases
WHERE source_database_id IS NOT NULL;

-- Database files
EXEC sp_msforeachdb '
USE [?];
SELECT DB_NAME() AS DatabaseName, name AS FileName, type_desc, physical_name, size, max_size
FROM sys.database_files;
';

-- SQL Agent operators (alerts, notifications)
SELECT name, email_address, enabled
FROM msdb.dbo.sysoperators;

-- Linked servers
SELECT name, data_source, provider, is_remote_login_enabled
FROM sys.servers;

-- Credentials
SELECT name, credential_identity, create_date
FROM sys.credentials;

-- End of script
PRINT '=== Enumeration Complete ===';
