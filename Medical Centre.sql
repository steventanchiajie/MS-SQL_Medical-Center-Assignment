--Security Requirements
--1. All database activities including data changes (DML query executions) and permission changes (DCL query executions) must be captured for auditing purposes.

USE master;
GO

-- Create server audit
CREATE SERVER AUDIT MedicalInfoSystemAudit
TO FILE 
(
    FILEPATH = 'C:\SQLAudits\',
    MAXSIZE = 100 MB,
    MAX_ROLLOVER_FILES = 10,
    RESERVE_DISK_SPACE = OFF
)
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO

-- Enable the server audit
ALTER SERVER AUDIT MedicalInfoSystemAudit WITH (STATE = ON);
GO

USE MedicalInfoSystem;
GO

-- Create database audit specification for DML auditing
CREATE DATABASE AUDIT SPECIFICATION MedicalInfoSystem_DMLAudit
FOR SERVER AUDIT MedicalInfoSystemAudit
ADD (INSERT, UPDATE, DELETE, SELECT ON DATABASE::MedicalInfoSystem BY public),
ADD (EXECUTE ON DATABASE::MedicalInfoSystem BY public)
WITH (STATE = ON);
GO

-- Create database audit specification for DDL auditing
CREATE DATABASE AUDIT SPECIFICATION MedicalInfoSystem_DDLAudit
FOR SERVER AUDIT MedicalInfoSystemAudit
ADD (SCHEMA_OBJECT_CHANGE_GROUP),
ADD (DATABASE_OBJECT_CHANGE_GROUP),
ADD (DATABASE_PRINCIPAL_CHANGE_GROUP)
WITH (STATE = ON);
GO

USE master;
GO

-- Create server audit specification for DCL auditing
CREATE SERVER AUDIT SPECIFICATION MedicalInfoSystem_DCLAudit
FOR SERVER AUDIT MedicalInfoSystemAudit
ADD (DATABASE_PERMISSION_CHANGE_GROUP),
ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PERMISSION_CHANGE_GROUP),
ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP)
WITH (STATE = ON);
GO

--2. All user logins (successful and unsuccessful) must be captured for auditing purposes.

USE master;
GO

-- Create the server audit for logins
CREATE SERVER AUDIT LoginAudit
TO APPLICATION_LOG
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);

-- Enable the audit
ALTER SERVER AUDIT LoginAudit WITH (STATE = ON);
GO

CREATE SERVER AUDIT SPECIFICATION LoginAuditSpec
FOR SERVER AUDIT LoginAudit
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (FAILED_LOGIN_GROUP)
WITH (STATE = ON);
GO

-- Create a login trigger
USE MedicalInfoSystem;
GO

CREATE OR ALTER TRIGGER LoginAuditTrigger 
ON ALL SERVER 
FOR LOGON 
AS 
BEGIN
    INSERT INTO MedicalInfoSystem.dbo.LoginAudit (UserID, LoginTime, IsSuccessful, IPAddress)
    VALUES (
        ORIGINAL_LOGIN(), 
        GETDATE(), 
        1, 
        CONVERT(varchar(48), CONNECTIONPROPERTY('client_net_address'))
    );
END;
GO
DISABLE TRIGGER LoginAuditTrigger ON ALL SERVER;
ENABLE TRIGGER LoginAuditTrigger ON ALL SERVER;
--3. Intentional or accidental deletion of data must be tracked and recovered easily if needed.

USE MedicalInfoSystem;
GO

-- Create a table to store deleted records
CREATE TABLE DeletedRecords (
    DeletedRecordID INT IDENTITY(1,1) PRIMARY KEY,
    TableName NVARCHAR(128),
    PrimaryKeyColumn NVARCHAR(128),
    PrimaryKeyValue NVARCHAR(MAX),
    DeletedData NVARCHAR(MAX),
    DeletedBy NVARCHAR(128),
    DeletedAt DATETIME2
);
GO

-- Create triggers for tracking deleted records (example for Patient table)
CREATE TRIGGER trg_Patient_DeleteTrack ON Patient
AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO DeletedRecords (TableName, PrimaryKeyColumn, PrimaryKeyValue, DeletedData, DeletedBy, DeletedAt)
    SELECT 
        'Patient',
        'PID',
        d.PID,
        (SELECT d.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
        SYSTEM_USER,
        GETDATE()
    FROM deleted d;
END;
GO

-- Create a procedure to recover deleted records
CREATE OR ALTER PROCEDURE RecoverDeletedRecord
    @DeletedRecordID INT
AS
BEGIN
    DECLARE @TableName NVARCHAR(128), @PrimaryKeyColumn NVARCHAR(128), @PrimaryKeyValue NVARCHAR(MAX), @DeletedData NVARCHAR(MAX);
    
    SELECT @TableName = TableName, @PrimaryKeyColumn = PrimaryKeyColumn, 
           @PrimaryKeyValue = PrimaryKeyValue, @DeletedData = DeletedData
    FROM DeletedRecords WHERE DeletedRecordID = @DeletedRecordID;
    
    DECLARE @SQL NVARCHAR(MAX);

    IF @TableName = 'Patient'
    BEGIN
        SET @SQL = N'
        IF NOT EXISTS (SELECT 1 FROM ' + QUOTENAME(@TableName) + ' WHERE ' + QUOTENAME(@PrimaryKeyColumn) + ' = @PrimaryKeyValue)
        BEGIN
            INSERT INTO ' + QUOTENAME(@TableName) + ' 
            SELECT * FROM OPENJSON(@DeletedData) WITH (
                PID VARCHAR(6),
                PName VARCHAR(100),
                PPhone VARCHAR(20),
                PaymentCardNo VARCHAR(100),
                EncryptedPassword VARBINARY(256),
                Salt UNIQUEIDENTIFIER
            )
        END';
    END
	ELSE IF @TableName = 'Doctor'
    BEGIN
        SET @SQL = N'
        IF NOT EXISTS (SELECT 1 FROM ' + QUOTENAME(@TableName) + ' WHERE ' + QUOTENAME(@PrimaryKeyColumn) + ' = @PrimaryKeyValue)
        BEGIN
            INSERT INTO ' + QUOTENAME(@TableName) + ' 
            SELECT * FROM OPENJSON(@DeletedData) WITH (
                DrID VARCHAR(6),
                DName VARCHAR(100),
                DPhone VARCHAR(20),
                EncryptedPassword VARBINARY(256),
                Salt UNIQUEIDENTIFIER
            )
        END';
	END
	ELSE IF @TableName = 'Diagnosis'
    BEGIN
        SET @SQL = N'
        IF NOT EXISTS (SELECT 1 FROM ' + QUOTENAME(@TableName) + ' WHERE ' + QUOTENAME(@PrimaryKeyColumn) + ' = @PrimaryKeyValue)
        BEGIN
            INSERT INTO ' + QUOTENAME(@TableName) + ' 
            SELECT * FROM OPENJSON(@DeletedData) WITH (
                DiagID INT,
                PatientID VARCHAR(6),
                DoctorID VARCHAR(6),
                DiagnosisDate DATETIME,
                Diagnosis VARCHAR(MAX),
				IsDeleted BIT
            )
        END';
	END
	ELSE
	BEGIN
		RAISERROR('Unsupported table for recovery',16, 1);
		RETURN;
	END

    EXEC sp_executesql @SQL, N'@PrimaryKeyValue NVARCHAR(MAX), @DeletedData NVARCHAR(MAX)', 
                       @PrimaryKeyValue, @DeletedData;
END;
GO

--4. Backups must be automated and the Recovery Point Objective (RPO) must be maximum 6 hours.

USE msdb;
GO

-- Create a job for automated backups
EXEC dbo.sp_add_job
    @job_name = N'MedicalInfoSystem_Backup_Every_6_Hours';

EXEC dbo.sp_add_jobstep
    @job_name = N'MedicalInfoSystem_Backup_Every_6_Hours',
    @step_name = N'Run Backup Procedure',
    @subsystem = N'TSQL',
    @command = N'
    DECLARE @BackupPath NVARCHAR(256) = N''C:\Backups\'';
    DECLARE @FileName NVARCHAR(256) = N''MedicalInfoSystem_'' + CONVERT(NVARCHAR(8), GETDATE(), 112) + 
                                       N''_'' + REPLACE(CONVERT(NVARCHAR(8), GETDATE(), 108), '':'', '''') + N''.bak'';
    DECLARE @BackupFile NVARCHAR(512) = @BackupPath + @FileName;

    BACKUP DATABASE MedicalInfoSystem 
    TO DISK = @BackupFile 
    WITH FORMAT, INIT, NAME = N''MedicalInfoSystem-Full Database Backup'', SKIP, NOREWIND, NOUNLOAD, STATS = 10;
    ';

EXEC dbo.sp_add_schedule
    @schedule_name = N'Every_6_Hours',
    @freq_type = 4, -- Daily
    @freq_interval = 1,
    @freq_subday_type = 8, -- Every n hours
    @freq_subday_interval = 6, -- Run every 6 hours
    @active_start_time = 000000; -- Start at midnight

EXEC dbo.sp_attach_schedule
    @job_name = N'MedicalInfoSystem_Backup_Every_6_Hours',
    @schedule_name = N'Every_6_Hours';

EXEC dbo.sp_add_jobserver
    @job_name = N'MedicalInfoSystem_Backup_Every_6_Hours';
GO

--5. Data must be classified and protected accordingly. Masked or Encryted data must be automatically unmasked or decrypted when retrieved by the rightful owner.

USE MedicalInfoSystem;
GO

-- Add data classification
ADD SENSITIVITY CLASSIFICATION TO 
    Patient.PName WITH (LABEL='Confidential', INFORMATION_TYPE='Name');
ADD SENSITIVITY CLASSIFICATION TO 
    Patient.PPhone WITH (LABEL='Confidential', INFORMATION_TYPE='Contact Information');
ADD SENSITIVITY CLASSIFICATION TO 
    Patient.PaymentCardNo WITH (LABEL='Highly Confidential', INFORMATION_TYPE='Financial');
GO

-- Create view for masked data
CREATE VIEW vw_MaskedPatient AS
SELECT
    PID,
    PName,
    CONCAT(LEFT(PPhone, 3), '****', RIGHT(PPhone, 4)) AS PPhone,
    'XXXX-XXXX-XXXX-' + RIGHT(PaymentCardNo, 4) AS PaymentCardNo
FROM Patient;
GO

-- Function to decrypt data
CREATE FUNCTION dbo.DecryptPaymentCard (@EncryptedCard VARBINARY(256))
RETURNS NVARCHAR(100)
WITH ENCRYPTION
AS
BEGIN
    DECLARE @DecryptedCard NVARCHAR(100)
    SET @DecryptedCard = CONVERT(NVARCHAR(100), DECRYPTBYKEY(@EncryptedCard))
    RETURN @DecryptedCard
END;
GO

-- Procedure to retrieve decrypted data (for authorized users only)
CREATE PROCEDURE GetDecryptedPatientData
    @PID VARCHAR(6)
AS
BEGIN
    IF IS_MEMBER('DataAdmin') = 1 OR IS_MEMBER('Doctor') = 1
    BEGIN
        SELECT
            PID,
            PName,
            PPhone,
            dbo.DecryptPaymentCard(CONVERT(VARBINARY(100), PaymentCardNo)) AS PaymentCardNo
        FROM Patient
        WHERE PID = @PID;
    END
    ELSE
    BEGIN
        RAISERROR('You do not have permission to view decrypted data.', 16, 1);
    END
END
GO

--6. Security and permissions must be managed using SQL Roles and properly documented in Authorization Matrix. There are 3 types of users in the system - Data Admin, Doctor and Patient

USE MedicalInfoSystem;
GO

-- Create roles
CREATE ROLE DataAdmin;
CREATE ROLE Doctor;
CREATE ROLE Patient;
GO

-- Grant permissions to roles
GRANT SELECT, INSERT, UPDATE ON Doctor TO DataAdmin;
GRANT SELECT, INSERT, UPDATE ON Patient TO DataAdmin;
GRANT SELECT ON MaskedPatient TO DataAdmin;
GRANT SELECT, INSERT ON Diagnosis TO Doctor;
GRANT SELECT ON MaskedPatient TO Doctor;
GRANT SELECT ON Diagnosis TO Doctor;
GRANT SELECT, UPDATE ON Doctor TO Doctor;
GRANT SELECT, UPDATE ON Patient TO Patient;
GRANT SELECT ON Diagnosis TO Patient;
GO

-- Create Authorization Matrix table
CREATE TABLE AuthorizationMatrix (
    RoleName NVARCHAR(128),
    TableName NVARCHAR(128),
    PermissionType NVARCHAR(50),
    CONSTRAINT PK_AuthorizationMatrix PRIMARY KEY (RoleName, TableName, PermissionType)
);
GO

-- Populate the Authorization Matrix
INSERT INTO AuthorizationMatrix VALUES
('DataAdmin', 'All Tables', 'SELECT, INSERT, UPDATE, DELETE'),
('Doctor', 'Patient', 'SELECT'),
('Doctor', 'Diagnosis', 'SELECT, INSERT, UPDATE'),
('Doctor', 'Doctor', 'SELECT, UPDATE'),
('Patient', 'vw_MaskedPatient', 'SELECT'),
('Patient', 'Diagnosis', 'SELECT');
GO

-- Procedure to manage role assignments
CREATE PROCEDURE ManageUserRole
    @UserName NVARCHAR(128),
    @RoleName NVARCHAR(128),
    @Action NVARCHAR(10) -- 'ADD' or 'REMOVE'
AS
BEGIN
    IF @Action = 'ADD'
    BEGIN
        EXEC sp_addrolemember @RoleName, @UserName;
    END
    ELSE IF @Action = 'REMOVE'
    BEGIN
        EXEC sp_droprolemember @RoleName, @UserName;
    END
    ELSE
    BEGIN
        RAISERROR('Invalid action. Use ''ADD'' or ''REMOVE''.', 16, 1);
    END
END;
GO

--7. Additional requirements for each role are as described below.
--Data Admin
--a. Can create new database users (you can assume the SQL login for users have been created).

USE MedicalInfoSystem;
GO

CREATE PROCEDURE CreateDatabaseUser
    @LoginName NVARCHAR(128),
    @UserName NVARCHAR(128),
    @RoleName NVARCHAR(128)
AS
BEGIN
    -- Create the database user
    CREATE USER [@UserName] FOR LOGIN [@LoginName];
    
    -- Add the user to the specified role
    EXEC sp_addrolemember @RoleName, @UserName;
END;
GO

-- Grant execute permission to DataAdmin role
GRANT EXECUTE ON CreateDatabaseUser TO DataAdmin;
GO

--b. Can perform permission management (grant, deny and revoke)

USE MedicalInfoSystem;
GO

CREATE PROCEDURE ManagePermissions
    @UserOrRole NVARCHAR(128),
    @ObjectName NVARCHAR(128),
    @PermissionType NVARCHAR(50),
    @Action NVARCHAR(10) -- 'GRANT', 'DENY', or 'REVOKE'
AS
BEGIN
    DECLARE @SQL NVARCHAR(MAX);
    SET @SQL = @Action + ' ' + @PermissionType + ' ON ' + @ObjectName + ' TO ' + @UserOrRole;
    EXEC sp_executesql @SQL;
END;
GO

-- Grant execute permission to DataAdmin role
GRANT EXECUTE ON ManagePermissions TO DataAdmin;
GO

--c. Can add and manage the doctor and patient records.

USE MedicalInfoSystem;
GO

-- These permissions were already granted in the role setup, but we'll repeat them here for clarity
GRANT SELECT, INSERT, UPDATE ON Doctor TO DataAdmin;
GRANT SELECT, INSERT, UPDATE ON Patient TO DataAdmin;
GO

--d. Must not have any access to access to any sensitive personal and patient’s diagnosis data.

USE MedicalInfoSystem;
GO

-- Revoke access to sensitive data
REVOKE SELECT ON Diagnosis FROM DataAdmin;
DENY SELECT ON Diagnosis TO DataAdmin;
Go

-- Create a view with non-sensitive patient data
CREATE VIEW vw_NonSensitivePatientData AS
SELECT
    PID,
    PName,
    PPhone
FROM Patient;

-- Grant access to the non-sensitive view
GRANT SELECT ON vw_NonSensitivePatientData TO DataAdmin3;
GO

--e. Can delete data but all deleted data must be tracked for auditing and for immediate recovery purposes.

USE MedicalInfoSystem;
GO

-- This functionality is already implemented in the DeletedRecords table and associated triggers
-- We just need to grant the necessary permissions to the DataAdmin role

GRANT DELETE ON Doctor TO DataAdmin;
GRANT DELETE ON Patient TO DataAdmin;
GRANT SELECT ON DeletedRecords TO DataAdmin;
Go

-- Create a procedure for DataAdmin to recover deleted records
CREATE PROCEDURE DataAdminRecoverRecord
    @DeletedRecordID INT
AS
BEGIN
    -- Check if the user is a member of the DataAdmin role
    IF IS_MEMBER('DataAdmin') = 1
    BEGIN
        EXEC RecoverDeletedRecord @DeletedRecordID;
    END
    ELSE
    BEGIN
        RAISERROR('You do not have permission to recover deleted records.', 16, 1);
    END
END;
GO

GRANT EXECUTE ON DataAdminRecoverRecord TO DataAdmin;
GO

--Doctors 
--a. Each doctor is given a unique database user id which can be used by them to log into the system

USE MedicalInfoSystem;
GO

CREATE OR ALTER PROCEDURE CreateDoctorUser
    @DoctorID VARCHAR(6),
    @Password NVARCHAR(128)
AS
BEGIN
    -- Create a login for the doctor
    DECLARE @SQL NVARCHAR(MAX);
    SET @SQL = N'CREATE LOGIN [Pt_' + @DoctorID + '] WITH PASSWORD = ''' + @Password + ''', CHECK_POLICY = ON;';
    EXEC sp_executesql @SQL;

    -- Create a user for the doctor
    SET @SQL = N'CREATE USER [Pt_' + @DoctorID + '] FOR LOGIN [Pt_' + @DoctorID + '];';
    EXEC sp_executesql @SQL;

    -- Add the user to the Doctor role
    SET @SQL = N'EXEC sp_addrolemember @rolename = ''Doctor'', @membername = ''Pt_' + @DoctorID + ''';';
    EXEC sp_executesql @SQL;
END;
GO
EXEC CreateDoctorUser @DoctorID = 'D010', @Password = '123', @DName = 'Jimmy', @DPhone = '019-876-2345';
EXEC CreateDoctorUser @DoctorID = 'D004', @Password = 'Doctor4@123';
EXEC CreateDoctorUser @DoctorID = 'D005', @Password = 'Doctor1@123';
EXEC CreateDoctorUser @DoctorID = 'D007', @Password = '123';

-- Insert information for Doctor D005
INSERT INTO dbo.Doctor (DrID, DName, DPhone, EncryptedPassword, Salt)
VALUES ('D006', 'Dr. HaoWei', '1234567890', 
        ENCRYPTBYPASSPHRASE('YourSecretPassphrase', '123'),
        NEWID());



-- Grant execute permission to DataAdmin role
GRANT EXECUTE ON CreateDoctorUser TO DataAdmin;
GO

--b. Doctors must be able to check and update their own personal data.

USE MedicalInfoSystem;
GO

-- Create a view for doctors to see their own data
CREATE VIEW vw_DoctorOwnData AS
SELECT DrID, DName, DPhone
FROM Doctor
WHERE DrID = SUBSTRING(USER_NAME(), 4, 6);
GO

GRANT SELECT, UPDATE ON vw_DoctorOwnData TO Doctor;
GO

-- Create a procedure for doctors to update their own data
CREATE PROCEDURE UpdateDoctorOwnData
    @DName VARCHAR(100) = NULL,
    @DPhone VARCHAR(20) = NULL
AS
BEGIN
    DECLARE @DrID VARCHAR(6) = SUBSTRING(USER_NAME(), 4, 6);
    
    UPDATE Doctor
    SET DName = ISNULL(@DName, DName),
        DPhone = ISNULL(@DPhone, DPhone)
    WHERE DrID = @DrID;
END;
GO

GRANT EXECUTE ON UpdateDoctorOwnData TO Doctor;
GO

--c. Doctors must be able to add new diagnosis details for patients and update them later.

USE MedicalInfoSystem;
GO

-- This permission was already granted in the role setup, but we'll repeat it here for clarity
GRANT SELECT, INSERT, UPDATE ON Diagnosis TO Doctor;
REVOKE UPDATE ON Diagnosis FROM Doctor;
Go

-- Create a procedure for doctors to add new diagnosis
CREATE PROCEDURE AddDiagnosis
    @PatientID VARCHAR(6),
    @DiagnosisText VARCHAR(MAX)
AS
BEGIN
    DECLARE @DoctorID VARCHAR(6) = SUBSTRING(USER_NAME(), 4, 6);
    
    INSERT INTO Diagnosis (PatientID, DoctorID, DiagnosisDate, Diagnosis)
    VALUES (@PatientID, @DoctorID, GETDATE(), @DiagnosisText);
END;
GO

GRANT EXECUTE ON AddDiagnosis TO Doctor;
Go

-- Create a procedure for doctors to update diagnosis
CREATE PROCEDURE UpdateDiagnosis
    @DiagID INT,
    @DiagnosisText VARCHAR(MAX)
AS
BEGIN
    DECLARE @DoctorID VARCHAR(6) = SUBSTRING(USER_NAME(), 4, 6);
    
    UPDATE Diagnosis
    SET Diagnosis = @DiagnosisText
    WHERE DiagID = @DiagID AND DoctorID = @DoctorID;
END;
GO

GRANT EXECUTE ON UpdateDiagnosis TO Doctor;
GO

--d. Doctors must be able view all patient’s diagnosis data even if it was added by other doctors but not update them.

USE MedicalInfoSystem;
GO

-- This permission was already granted in the role setup, but we'll repeat it here for clarity
GRANT SELECT ON Diagnosis TO Doctor;
Go

-- Create a view for doctors to see all diagnosis data
CREATE VIEW vw_AllDiagnosis AS
SELECT d.DiagID, d.PatientID, p.PName, d.DoctorID, dr.DName AS DoctorName, d.DiagnosisDate, d.Diagnosis
FROM Diagnosis d
JOIN Patient p ON d.PatientID = p.PID
JOIN Doctor dr ON d.DoctorID = dr.DrID;
GO

GRANT SELECT ON vw_AllDiagnosis TO Doctor;
GO

--e. Doctors must NOT be able to delete any data.

USE MedicalInfoSystem;
GO

-- Explicitly deny delete permissions
DENY DELETE ON Doctor TO Doctor;
DENY DELETE ON Patient TO Doctor;
DENY DELETE ON Diagnosis TO Doctor;
GO

--Patients 
--a. Each patient is given a unique database user id which can be used by them to log into the system

USE MedicalInfoSystem;
GO

CREATE OR ALTER PROCEDURE CreatePatientUser
    @PatientID VARCHAR(6),
    @Password NVARCHAR(128)
AS
BEGIN
    -- Create a login for the patient
    DECLARE @SQL NVARCHAR(MAX);
    SET @SQL = N'CREATE LOGIN [Pt_' + @PatientID + '] WITH PASSWORD = ''' + @Password + ''', CHECK_POLICY = ON;';
    EXEC sp_executesql @SQL;

    -- Create a user for the patient
    SET @SQL = N'CREATE USER [Pt_' + @PatientID + '] FOR LOGIN [Pt_' + @PatientID + '];';
    EXEC sp_executesql @SQL;

    -- Add the user to the Patient role
    SET @SQL = N'EXEC sp_addrolemember @rolename = ''Patient'', @membername = ''Pt_' + @PatientID + ''';';
    EXEC sp_executesql @SQL;
END;
GO

EXEC CreatePatientUser @PatientID = 'P004', @Password = 'Patient4@123';
EXEC CreatePatientUser @PatientID = 'P001', @Password = 'Patient1@123';
EXEC CreatePatientUser @PatientID = 'P003', @Password = '123';

-- Grant execute permission to DataAdmin role
GRANT EXECUTE ON CreatePatientUser TO DataAdmin;
GO
INSERT INTO dbo.Doctor (DrID, DName, DPhone, EncryptedPassword, Salt)
VALUES ('P012', 'Amin', '012-123-4567', 
        ENCRYPTBYPASSPHRASE('YourSecretPassphrase', '123'),
        NEWID());
--b. Patients must be able to check and update their own personal data.

USE MedicalInfoSystem;
GO

-- Create a view for patients to see their own data
CREATE VIEW vw_PatientOwnData AS
SELECT PID, PName, PPhone, PaymentCardNo
FROM Patient
WHERE PID = SUBSTRING(USER_NAME(), 4, 6);  -- Assuming the username format is 'Pt_XXXXXX'
GO

GRANT SELECT, UPDATE ON vw_PatientOwnData TO Patient;
GO

-- Create a procedure for patients to update their own data
CREATE PROCEDURE UpdatePatientOwnData
    @PName VARCHAR(100) = NULL,
    @PPhone VARCHAR(20) = NULL,
    @PaymentCardNo VARCHAR(100) = NULL
AS
BEGIN
    DECLARE @PID VARCHAR(6) = SUBSTRING(USER_NAME(), 4, 6);
    
    UPDATE Patient
    SET PName = ISNULL(@PName, PName),
        PPhone = ISNULL(@PPhone, PPhone),
        PaymentCardNo = ISNULL(@PaymentCardNo, PaymentCardNo)
    WHERE PID = @PID;
END;
GO

GRANT EXECUTE ON UpdatePatientOwnData TO Patient;
GO

--c. Patients must be able to check their own diagnosis details.

USE MedicalInfoSystem;
GO

-- Create a view for patients to see their own diagnosis data
CREATE VIEW vw_PatientOwnDiagnosis AS
SELECT d.DiagID, d.DiagnosisDate, d.Diagnosis, dr.DName AS DoctorName
FROM Diagnosis d
JOIN Doctor dr ON d.DoctorID = dr.DrID
WHERE d.PatientID = SUBSTRING(USER_NAME(), 4, 6);  -- Assuming the username format is 'Pt_XXXXXX'
GO

GRANT SELECT ON vw_PatientOwnDiagnosis TO Patient;
GO

--d. Patients must not be able to access other patients’ personal or diagnosis details

USE MedicalInfoSystem;
GO

-- This is already enforced by the views we created (vw_PatientOwnData and vw_PatientOwnDiagnosis)
-- We'll add an extra layer of security using row-level security

-- Create a function for row-level security
CREATE FUNCTION fn_PatientSecurity(@PID VARCHAR(6))
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_securityResult 
WHERE @PID = SUBSTRING(USER_NAME(), 4, 6)
    OR IS_MEMBER('Doctor') = 1 
    OR IS_MEMBER('DataAdmin') = 1
GO

-- Create a security policy
CREATE SECURITY POLICY PatientSecurityPolicy
ADD FILTER PREDICATE dbo.fn_PatientSecurity(PID) ON dbo.Patient,
ADD BLOCK PREDICATE dbo.fn_PatientSecurity(PatientID) ON dbo.Diagnosis
WITH (STATE = ON);
GO

--e. Patients must NOT be able to delete any data.

USE MedicalInfoSystem;
GO
-- Explicitly deny delete permissions
DENY DELETE ON Patient TO Patient;
DENY DELETE ON Diagnosis TO Patient;
GO
