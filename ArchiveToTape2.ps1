<# 
Enhanced Folder-Level Tape Archiving Script with SQLite Database Logging
Version 20.0 - Complete with All Features including Dual-Tape Support, Secure Metadata, and Source Cleanup
#>

# ============================
# CONFIGURATION - EDIT THESE
# ============================
$SourceServers      = @("x:", "y:","z:")   # servers to scan
$SourceBasePath     = "Testing\"            # path on each server (relative)

# PRIMARY TAPE DRIVE (Active)
$TapeDrive          = "F:"                  # LTFS mount letter (include colon)

# SECONDARY TAPE DRIVE (Future Implementation - Commented)
# $TapeDrive2         = "G:"                # Secondary LTFS mount for dual backup
# $EnableDualTape     = $false              # Set to $true when ready to enable dual tapes

$LogFile            = "C:\TapeAutomation\Logs\ArchiveLog.txt"
$MaxLogSize         = 10MB                  # rotate when >= this (bytes)
$MaxLogFiles        = 10                    # keep only 10 most recent log files
$TapeFullThreshold  = 500 * 1GB           # 500 GB reserve buffer (adjust as needed)
$DaysThreshold      = 0                     # archive only folders older than X days
$MaxJobDurationHours= 20                    # long-job alert threshold

# Enhanced retry configuration
$NetworkRetries     = 3
$NetworkRetryDelay  = 10   # seconds
$TapeRetryAttempts  = 5    # Number of retry attempts for tape operations
$TapeRetryDelay     = 30   # Seconds between tape retry attempts

# SQLite DB
$DatabasePath       = "C:\TapeAutomation\TapeArchive.db"
$DatabaseBackupPath = "\\Test-srv\InstallationFiles\Database Test\TapeArchive.db"  # Secondary backup location
$DatabaseTable      = "TapeArchiveLog"

# Email (will use Windows Credential Manager for smtp.gmail.com)
$EmailFrom          = "it.test@test.com.au"
$EmailTo            = "testing@test.com.au"
$SMTPServer         = "smtp.gmail.com"
$SMTPPort           = 587
$UseSSL             = $true
$EmailUser          = "it.test@infinitypath.com.au"

# ============================
# GLOBALS
# ============================
$ScriptStartTime = Get-Date
$script:EmailSentForCurrentTape = $false
$script:JobTimeoutAlertSent = $false
$script:TapeLabel = $null
$script:TapeUniqueID = $null
$script:EmailCredential = $null
$script:PreviousTapeLabel = $null
$script:PreviousTapeUniqueID = $null
$script:TapeDriveAvailable = $false
$script:CurrentTapeSwapAttempt = 0
$script:FailedServers = @()
$script:ProcessedServers = @()

# Dual Tape Globals (Future Use)
# $script:TapeLabel2 = $null
# $script:TapeUniqueID2 = $null
# $script:TapeDrive2Available = $false

# ============================
# LOGGING + ROTATION - DASHCAM STYLE (KEEP ONLY 10 MOST RECENT)
# ============================
Function Log-Message {
    param([string]$msg)
    try {
        $logDir = Split-Path $LogFile -Parent
        if (-not (Test-Path $logDir)) { 
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null 
            Write-Host "Created log directory: $logDir" -ForegroundColor Green
        }

        # Check if current log file needs rotation
        if (Test-Path $LogFile) {
            $logSize = (Get-Item $LogFile).Length
            if ($logSize -ge $MaxLogSize) {
                Write-Host "[SYSTEM] Log file reached size limit ($([Math]::Round($logSize/1MB,2)) MB), rotating..." -ForegroundColor Yellow
                Rotate-LogFiles
            }
        }

        $timestampedMsg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
        Add-Content -Path $LogFile -Value $timestampedMsg
        Write-Host $timestampedMsg -ForegroundColor Cyan
    } catch {
        Write-Host "Log-Message failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Function Rotate-LogFiles {
    try {
        $logDir = Split-Path $LogFile -Parent
        $logBaseName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile)
        $logExtension = [System.IO.Path]::GetExtension($LogFile)
        
        # Generate timestamp for the new rotated log
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $rotatedLog = Join-Path $logDir "$logBaseName`_$timestamp$logExtension"
        
        # If current log exists, rotate it
        if (Test-Path $LogFile) {
            Move-Item -Path $LogFile -Destination $rotatedLog -Force
            Write-Host "[SYSTEM] Log file rotated: $rotatedLog" -ForegroundColor Green
            
            # Create new empty log file
            $null = New-Item -Path $LogFile -ItemType File -Force
            Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - [SYSTEM] New log file started after rotation"
        }
        
        # Clean up old log files - keep only the $MaxLogFiles most recent
        $allLogFiles = Get-ChildItem -Path $logDir -Filter "$logBaseName*$logExtension" | 
                      Sort-Object LastWriteTime -Descending
        
        if ($allLogFiles.Count -gt $MaxLogFiles) {
            $filesToDelete = $allLogFiles | Select-Object -Skip $MaxLogFiles
            foreach ($oldFile in $filesToDelete) {
                try {
                    Remove-Item -Path $oldFile.FullName -Force
                    Write-Host "[SYSTEM] Deleted old log file: $($oldFile.Name)" -ForegroundColor Yellow
                } catch {
                    Write-Host "[WARNING] Could not delete old log file: $($oldFile.Name) - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            Write-Host "[SYSTEM] Log cleanup completed. Kept $MaxLogFiles most recent files, deleted $($filesToDelete.Count) old files." -ForegroundColor Green
        }
        
        # Log current log file status
        $currentFiles = Get-ChildItem -Path $logDir -Filter "$logBaseName*$logExtension"
        Write-Host "[SYSTEM] Current log files: $($currentFiles.Count) files (max: $MaxLogFiles)" -ForegroundColor Cyan
        
    } catch {
        Write-Host "Log rotation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Function Initialize-LogCleanup {
    try {
        $logDir = Split-Path $LogFile -Parent
        if (Test-Path $logDir) {
            $logBaseName = [System.IO.Path]::GetFileNameWithoutExtension($LogFile)
            $logExtension = [System.IO.Path]::GetExtension($LogFile)
            
            $allLogFiles = Get-ChildItem -Path $logDir -Filter "$logBaseName*$logExtension" | 
                          Sort-Object LastWriteTime -Descending
            
            if ($allLogFiles.Count -gt $MaxLogFiles) {
                $filesToDelete = $allLogFiles | Select-Object -Skip $MaxLogFiles
                foreach ($oldFile in $filesToDelete) {
                    try {
                        Remove-Item -Path $oldFile.FullName -Force
                        Write-Host "Initial cleanup: Deleted old log file: $($oldFile.Name)" -ForegroundColor Yellow
                    } catch {
                        Write-Host "Initial cleanup: Could not delete $($oldFile.Name) - $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                Write-Host "Initial log cleanup: Kept $MaxLogFiles most recent files, deleted $($filesToDelete.Count) old files." -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "Initial log cleanup failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================
# DATABASE BACKUP FUNCTION
# ============================
Function Backup-Database {
    try {
        Log-Message "Starting database backup process..."
        
        # Check if primary database exists
        if (-not (Test-Path $DatabasePath)) {
            Log-Message "WARNING: Primary database not found at $DatabasePath"
            return $false
        }
        
        # Backup to secondary location
        $backupDir = Split-Path $DatabaseBackupPath -Parent
        if (-not (Test-Path $backupDir)) {
            Log-Message "Creating backup directory: $backupDir"
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        
        # Create backup with timestamp
        $backupFileName = "TapeArchive_$(Get-Date -Format 'yyyyMMdd_HHmmss').db"
        $timestampedBackupPath = Join-Path $backupDir $backupFileName
        
        # Copy database file
        Copy-Item -Path $DatabasePath -Destination $timestampedBackupPath -Force
        Log-Message "SUCCESS: Database backed up to: $timestampedBackupPath"
        
        # Also update the main backup file (without timestamp for latest version)
        Copy-Item -Path $DatabasePath -Destination $DatabaseBackupPath -Force
        Log-Message "SUCCESS: Database backup updated: $DatabaseBackupPath"
        
        # Clean up old backup files (keep last 5)
        $oldBackups = Get-ChildItem -Path $backupDir -Filter "TapeArchive_*.db" | 
                     Sort-Object LastWriteTime -Descending | 
                     Select-Object -Skip 5
        
        foreach ($oldBackup in $oldBackups) {
            try {
                Remove-Item -Path $oldBackup.FullName -Force
                Log-Message "Cleaned up old backup: $($oldBackup.Name)"
            } catch {
                Log-Message "WARNING: Could not delete old backup $($oldBackup.Name): $($_.Exception.Message)"
            }
        }
        
        return $true
        
    } catch {
        Log-Message "ERROR: Database backup failed: $($_.Exception.Message)"
        return $false
    }
}

# ============================
# EMAIL FUNCTIONS
# ============================
Function Get-EmailCredential {
    try {
        if ($script:EmailCredential) {
            return $script:EmailCredential
        }

        Log-Message "Attempting to retrieve SMTP credentials from Windows Credential Manager for: $SMTPServer"
        
        # Method 1: Direct Vault access using CredentialManager module
        $credential = Get-CredentialFromVault -Target $SMTPServer
        if ($credential) {
            $script:EmailCredential = $credential
            return $credential
        }
        
        # Method 2: Try alternative target names
        $alternativeTargets = @(
            "smtp.gmail.com",
            "WindowsCredentials:smtp.gmail.com",
            "LegacyGeneric:smtp.gmail.com",
            "MicrosoftAccount:smtp.gmail.com"
        )
        
        foreach ($target in $alternativeTargets) {
            $credential = Get-CredentialFromVault -Target $target
            if ($credential) {
                $script:EmailCredential = $credential
                Log-Message "SUCCESS: Found credentials using alternative target: $target"
                return $credential
            }
        }
        
        # Method 3: Manual credential entry as fallback
        Log-Message "WARNING: No stored credentials found. Prompting for manual entry..."
        $manualCred = Get-Credential -Message "Enter SMTP credentials for $SMTPServer" -UserName $EmailUser
        if ($manualCred) {
            $script:EmailCredential = $manualCred
            Log-Message "Using manually entered credentials"
            return $manualCred
        }
        
        throw "No credentials available for $SMTPServer"
        
    } catch {
        Log-Message "ERROR: Failed to retrieve email credentials: $($_.Exception.Message)"
        throw
    }
}

Function Get-CredentialFromVault {
    param([string]$Target)
    
    try {
        if (Get-Module -ListAvailable -Name CredentialManager) {
            Import-Module CredentialManager -ErrorAction SilentlyContinue
            Log-Message "Checking CredentialManager for target: $Target"
            
            $storedCred = Get-StoredCredential -Target $Target -ErrorAction SilentlyContinue
            if ($storedCred) {
                Log-Message "SUCCESS: Retrieved credentials using CredentialManager for: $Target"
                return $storedCred
            }
            
            Log-Message "Listing all stored credentials to find match..."
            $allCreds = Get-StoredCredential -ErrorAction SilentlyContinue
            if ($allCreds) {
                $matchingCred = $allCreds | Where-Object { 
                    $_.Target -like "*$SMTPServer*" -or 
                    $_.UserName -eq $EmailUser -or
                    $_.UserName -like "*$EmailUser*"
                }
                if ($matchingCred) {
                    Log-Message "SUCCESS: Found matching credential by username: $($matchingCred.UserName)"
                    return $matchingCred
                }
            }
        }
        
        # Install CredentialManager module if not available
        Log-Message "CredentialManager module not installed. Attempting to install..."
        try {
            Install-Module -Name CredentialManager -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Import-Module CredentialManager -Force
            Log-Message "CredentialManager module installed successfully"
            
            $storedCred = Get-StoredCredential -Target $Target -ErrorAction SilentlyContinue
            if ($storedCred) {
                Log-Message "SUCCESS: Retrieved credentials after module installation for: $Target"
                return $storedCred
            }
        } catch {
            Log-Message "WARNING: Could not install CredentialManager module: $($_.Exception.Message)"
        }
        
        return $null
        
    } catch {
        Log-Message "WARNING: Vault access method failed: $($_.Exception.Message)"
        return $null
    }
}

Function Send-Email {
    param(
        [string]$Subject,
        [string]$Body,
        [bool]$IsError = $false
    )
    try {
        if (-not $SMTPServer -or -not $EmailFrom -or -not $EmailTo) {
            Write-Host "EMAIL CONFIG MISSING: Cannot send email. Subject: $Subject" -ForegroundColor Red
            return $false
        }

        $credential = Get-EmailCredential
        if (-not $credential) {
            $errorMsg = "Could not retrieve SMTP credentials from Windows Credential Manager for $SMTPServer"
            Log-Message "ERROR: $errorMsg"
            return $false
        }

        $mailParams = @{
            From        = $EmailFrom
            To          = $EmailTo
            Subject     = $Subject
            Body        = $Body
            SmtpServer  = $SMTPServer
            Port        = $SMTPPort
            UseSsl      = $UseSSL
            Credential  = $credential
            ErrorAction = 'Stop'
        }

        Log-Message "Attempting to send email to $EmailTo..."
        Send-MailMessage @mailParams
        Log-Message "Email sent successfully: $Subject"
        return $true
        
    } catch {
        $errorMsg = "Failed to send email. Error: $($_.Exception.Message)"
        Log-Message "ERROR: $errorMsg"
        return $false
    }
}

Function Test-EmailCredentialSetup {
    try {
        Log-Message "Testing email credential setup..."
        $credential = Get-EmailCredential
        if ($credential) {
            Log-Message "SUCCESS: Email credentials retrieved from Windows Credential Manager"
            return $true
        } else {
            Log-Message "FAILED: Could not retrieve email credentials"
            return $false
        }
    } catch {
        Log-Message "ERROR: Email credential test failed: $($_.Exception.Message)"
        return $false
    }
}

# ============================
# STARTUP AND COMPLETION EMAILS
# ============================
Function Send-StartupEmail {
    try {
        $subject = "Tape Archive Job Started"
        $body = @"
TAPE ARCHIVE JOB INITIATED

Job started at: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
Server: $env:COMPUTERNAME
Script: $($MyInvocation.ScriptName)

Configuration:
- Source Servers: $($SourceServers -join ', ')
- Tape Drive: $TapeDrive
- Days Threshold: $DaysThreshold days

Current Tape Information:
- Tape Label: $($script:TapeLabel)
- Tape Unique ID: $($script:TapeUniqueID)

The script will now begin processing servers. You will receive a completion report when the job finishes.

This is an automated notification from the Tape Archiving System.
"@
        
        if (Send-Email -Subject $subject -Body $body) {
            Log-Message "Startup email sent successfully"
            return $true
        } else {
            Log-Message "WARNING: Failed to send startup email"
            return $false
        }
        
    } catch {
        Log-Message "ERROR: Startup email function failed: $($_.Exception.Message)"
        return $false
    }
}

Function Send-CompletionEmail {
    param([TimeSpan]$Duration)
    
    try {
        $completionTime = Get-Date
        $durationFormatted = $Duration.ToString('hh\:mm\:ss')
        
        $subject = "Tape Archive Job Completed"
        
        # Build the body with detailed information
        $body = @"
TAPE ARCHIVE JOB COMPLETION REPORT

Job Summary:
- Start Time: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
- End Time: $($completionTime.ToString('yyyy-MM-dd HH:mm:ss'))
- Total Duration: $durationFormatted
- Server: $env:COMPUTERNAME

Tape Information:
- Current Tape: $($script:TapeLabel) [$($script:TapeUniqueID)]
- Previous Tape: $(if ($script:PreviousTapeLabel) { "$script:PreviousTapeLabel [$script:PreviousTapeUniqueID]" } else { "N/A" })
"@

        # Add successful servers section
        if ($script:ProcessedServers.Count -gt 0) {
            $body += @"

SUCCESSFUL SERVERS:
$($script:ProcessedServers -join "`n")
"@
        }

        # Add failed servers section with details
        if ($script:FailedServers.Count -gt 0) {
            $body += @"

FAILED SERVERS (Requires Attention):
$($script:FailedServers -join "`n")
"@
        }

        # Add tape swap information if applicable
        if ($script:PreviousTapeLabel) {
            $body += @"

Tape Swap Information:
- Tape swap was performed during this job
- Previous tape: $script:PreviousTapeLabel [$script:PreviousTapeUniqueID]
- Current tape: $script:TapeLabel [$script:TapeUniqueID]
"@
        }

        # Add database information
        $body += @"

Database Information:
- Primary Location: $DatabasePath
- Backup Location: $DatabaseBackupPath
- Database Status: $(if (Test-Path $DatabasePath) { 'OK' } else { 'MISSING' })

Log Files:
- Current Log: $LogFile
- Log Rotation: $MaxLogFiles most recent files kept

$(if ($script:FailedServers.Count -gt 0) {
"ACTION REQUIRED:
Please check the connectivity to the failed servers listed above.
The script will attempt to process them again in the next run."
} else {
"All servers processed successfully. No action required."
})

This is an automated report from the Tape Archiving System.
"@
        
        if (Send-Email -Subject $subject -Body $body) {
            Log-Message "Completion email sent successfully"
            return $true
        } else {
            Log-Message "WARNING: Failed to send completion email"
            return $false
        }
        
    } catch {
        Log-Message "ERROR: Completion email function failed: $($_.Exception.Message)"
        return $false
    }
}

# ============================
# NETWORK PATH RETRY
# ============================
Function Test-NetworkPath {
    param(
        [string]$Path,
        [int]$Retries = $NetworkRetries,
        [int]$DelaySeconds = $NetworkRetryDelay
    )
    for ($i=1; $i -le $Retries; $i++) {
        if (Test-Path -Path $Path -PathType Container) { return $true }
        Write-Warning "Attempt $i/$Retries - path $Path not available. Retrying in $DelaySeconds seconds..."
        Start-Sleep -Seconds $DelaySeconds
    }
    return $false
}

# ============================
# SQLITE DATABASE FUNCTIONS
# ============================
Function Initialize-SQLiteDatabase {
    try {
        if (-not (Get-Module -Name PSSQLite -ListAvailable)) {
            Log-Message "Installing PSSQLite module..."
            Install-Module -Name PSSQLite -Force -Scope CurrentUser -AllowClobber
        }
        Import-Module PSSQLite -Force

        $dbDir = Split-Path $DatabasePath -Parent
        if (-not (Test-Path $dbDir)) { New-Item -Path $dbDir -ItemType Directory -Force | Out-Null; Log-Message "Created DB directory: $dbDir" }

        $databaseExists = Test-Path $DatabasePath
        if (-not $databaseExists) {
            Log-Message "Creating new SQLite database and schema..."
            $query = @"
CREATE TABLE $DatabaseTable (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    SourcePath TEXT NOT NULL,
    TapeLabel TEXT,
    TapeUniqueID TEXT,
    SizeBytes INTEGER,
    FolderHash TEXT NOT NULL,
    ArchiveDate TEXT NOT NULL,
    FileCount INTEGER DEFAULT 0,
    LogTimestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    Status TEXT NOT NULL,
    ErrorMessage TEXT,
    ServerName TEXT NOT NULL,
    SourceDeleted INTEGER DEFAULT 0,
    SourceDeletedDate TEXT
);
CREATE INDEX IX_SourcePath ON $DatabaseTable (SourcePath);
CREATE INDEX IX_TapeLabel ON $DatabaseTable (TapeLabel);
CREATE INDEX IX_TapeUniqueID ON $DatabaseTable (TapeUniqueID);
CREATE INDEX IX_ArchiveDate ON $DatabaseTable (ArchiveDate);
CREATE INDEX IX_Status ON $DatabaseTable (Status);
CREATE INDEX IX_FolderHash ON $DatabaseTable (FolderHash);
CREATE INDEX IX_ServerName ON $DatabaseTable (ServerName);
CREATE INDEX IX_SourceDeleted ON $DatabaseTable (SourceDeleted);
CREATE UNIQUE INDEX IF NOT EXISTS IX_SourceHashSuccess ON $DatabaseTable (SourcePath, FolderHash) WHERE Status='SUCCESS';

CREATE TABLE IF NOT EXISTS TapeRegistry (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    TapeLabel TEXT NOT NULL,
    TapeUniqueID TEXT NOT NULL UNIQUE,
    TapeFingerprint TEXT NOT NULL UNIQUE,
    TapeNumber INTEGER,
    FirstSeen TEXT DEFAULT CURRENT_TIMESTAMP,
    LastSeen TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS IX_TapeFingerprint ON TapeRegistry (TapeFingerprint);
CREATE INDEX IF NOT EXISTS IX_TapeUniqueID ON TapeRegistry (TapeUniqueID);
"@
            Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
            Log-Message "SUCCESS: DB created at $DatabasePath"
        } else {
            Log-Message "DB exists; checking schema..."
            Update-DatabaseSchemaForCleanup
            Update-TapeRegistrySchema
            Log-Message "SUCCESS: DB schema ensured/updated."
        }
        return $true
    } catch {
        Log-Message "ERROR: Failed to initialize DB: $($_.Exception.Message)"
        Send-Email -Subject "Tape Archive Error: DB Init Failed" -Body "Error: $($_.Exception.Message)" -IsError $true
        return $false
    }
}

Function Update-DatabaseSchemaForCleanup {
    try {
        Import-Module PSSQLite -Force
        
        # Check if SourceDeleted column exists
        $columns = Invoke-SqliteQuery -Query "PRAGMA table_info($DatabaseTable)" -DataSource $DatabasePath
        $hasSourceDeleted = $columns | Where-Object { $_.name -eq "SourceDeleted" }
        
        if (-not $hasSourceDeleted) {
            Log-Message "Adding SourceDeleted column to track source cleanup..."
            Invoke-SqliteQuery -Query "ALTER TABLE $DatabaseTable ADD COLUMN SourceDeleted INTEGER DEFAULT 0" -DataSource $DatabasePath
            Invoke-SqliteQuery -Query "ALTER TABLE $DatabaseTable ADD COLUMN SourceDeletedDate TEXT" -DataSource $DatabasePath
            Invoke-SqliteQuery -Query "CREATE INDEX IF NOT EXISTS IX_SourceDeleted ON $DatabaseTable (SourceDeleted)" -DataSource $DatabasePath
            Log-Message "SUCCESS: Database schema updated for source cleanup tracking"
        }
        
        return $true
    } catch {
        Log-Message "WARNING: Could not update database schema for cleanup: $($_.Exception.Message)"
        return $false
    }
}

Function Update-TapeRegistrySchema {
    try {
        Import-Module PSSQLite -Force
        
        # Check if TapeNumber column exists
        $columns = Invoke-SqliteQuery -Query "PRAGMA table_info(TapeRegistry)" -DataSource $DatabasePath
        $hasTapeNumber = $columns | Where-Object { $_.name -eq "TapeNumber" }
        
        if (-not $hasTapeNumber) {
            Log-Message "Adding TapeNumber column to TapeRegistry table..."
            Invoke-SqliteQuery -Query "ALTER TABLE TapeRegistry ADD COLUMN TapeNumber INTEGER" -DataSource $DatabasePath
        }
        
    } catch {
        Log-Message "WARNING: Could not update TapeRegistry schema: $($_.Exception.Message)"
    }
}

# ============================
# FOLDER HASH (SHA256 on concatenated file metadata + file hashes)
# ============================
Function Get-FolderHash {
    param([string]$FolderPath)
    try {
        Log-Message "Calculating hash for folder: $FolderPath"
        $files = Get-ChildItem -Path $FolderPath -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName
        if ($files.Count -eq 0) {
            $hashString = $FolderPath + "|EMPTY"
            $hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($hashString)))).Hash
            Log-Message "Empty folder hash: $hash"
            return $hash
        }
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $stream = [System.IO.MemoryStream]::new()
        foreach ($file in $files) {
            try {
                $fileInfo = "{0}|{1}|{2}" -f $file.FullName, $file.Length, $file.LastWriteTime.Ticks
                $fileInfoBytes = [System.Text.Encoding]::UTF8.GetBytes($fileInfo)
                $stream.Write($fileInfoBytes, 0, $fileInfoBytes.Length)
                $fileHash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($fileHash) {
                    $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($fileHash.Hash)
                    $stream.Write($hashBytes, 0, $hashBytes.Length)
                }
            } catch {
                Log-Message "WARNING: Skipped hashing file $($file.FullName): $($_.Exception.Message)"
            }
        }
        $stream.Position = 0
        $hashBytes = $hasher.ComputeHash($stream)
        $hash = [BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
        $stream.Close(); $hasher.Dispose()
        Log-Message "Folder hash calculated: $hash"
        return $hash
    } catch {
        Log-Message "ERROR: Hash calc failed for ${FolderPath}: $($_.Exception.Message)"
        throw
    }
}

# ============================
# ALREADY ARCHIVED CHECK (SUCCESS ONLY)
# ============================
Function Test-FolderAlreadyArchived {
    param([string]$FolderPath, [string]$FolderHash)
    try {
        Import-Module PSSQLite -Force
        $query = "SELECT COUNT(*) as Count FROM $DatabaseTable WHERE FolderHash = '$FolderHash' AND Status = 'SUCCESS'"
        $result = Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        $isArchived = $result.Count -gt 0
        if ($isArchived) { Log-Message "Folder already archived (hash match): $FolderPath" }
        return $isArchived
    } catch {
        Log-Message "WARNING: Could not check DB for folder archive: $($_.Exception.Message)"
        return $false
    }
}

# ============================
# SAFE DB LOGGING (ONLY SUCCESS RECORDS)
# ============================
Function Write-DatabaseLog {
    param(
        [string]$SourcePath,
        [string]$TapeLabel,
        [string]$TapeUniqueID,
        [long]$SizeBytes,
        [string]$FolderHash,
        [string]$Status,
        [int]$FileCount = 0,
        [string]$ErrorMessage = $null,
        [string]$ServerName = $null
    )
    try {
        # Only write SUCCESS records to database
        if ($Status -ne "SUCCESS") {
            Log-Message "DB SKIP: $SourcePath -> Status: $Status (Logged to file only)"
            return
        }

        Import-Module PSSQLite -Force

        if (-not $ServerName) { $ServerName = "UNKNOWN" }
        if (-not $ErrorMessage) { $ErrorMessage = "NONE" }

        $e = [System.Security.SecurityElement]
        $src = $e::Escape($SourcePath)
        $lab = $e::Escape($TapeLabel)
        $uniq = if ($TapeUniqueID) { $e::Escape($TapeUniqueID) } else { "" }
        $hsh = $e::Escape($FolderHash)
        $sts = $e::Escape($Status)
        $srv = $e::Escape($ServerName)
        $err = $e::Escape($ErrorMessage)
        $archiveDate = (Get-Date -Format "yyyy-MM-dd")

        $query = @"
INSERT OR IGNORE INTO $DatabaseTable
    (SourcePath, TapeLabel, TapeUniqueID, SizeBytes, FolderHash, ArchiveDate, FileCount, Status, ErrorMessage, ServerName)
VALUES
    ('$src', '$lab', '$uniq', $SizeBytes, '$hsh', '$archiveDate', $FileCount, '$sts', '$err', '$srv')
"@
        $result = Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        if ($result -eq 0) {
            Log-Message "DB DUPLICATE SKIPPED: $SourcePath (already exists in database)"
        } else {
            Log-Message "DB SUCCESS: $SourcePath -> Tape: $TapeLabel [$TapeUniqueID]"
        }
    } catch {
        Log-Message "ERROR: Failed to write DB log: $($_.Exception.Message)"
    }
}

# ============================
# SECURE TAPE METADATA FUNCTIONS
# ============================
Function New-SecureTapeMetadata {
    param(
        [string]$DriveLetter = $TapeDrive,
        [string]$TapeUniqueID,
        [string]$TapeLabel,
        [int]$TapeNumber
    )
    
    try {
        $tapeDriveRoot = "${DriveLetter}\"
        if (-not (Test-Path -Path $tapeDriveRoot -PathType Container)) {
            throw "Tape drive not accessible"
        }

        # Use multiple hidden locations and names
        $metadataLocations = @(
            Join-Path $tapeDriveRoot "~tape_metadata.dat"
            Join-Path $tapeDriveRoot "SystemVolume\.tapeid"
            Join-Path $tapeDriveRoot "\.tape_registry"
        )
        
        $metadataContent = @{
            UniqueID = $TapeUniqueID
            Label = $TapeLabel
            TapeNumber = $TapeNumber
            Created = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            CreatedBy = "TapeArchivingScript"
            Signature = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($TapeUniqueID))).Hash
        } | ConvertTo-Json -Compress
        
        $successCount = 0
        foreach ($metadataFile in $metadataLocations) {
            try {
                # Create directory if needed
                $metaDir = Split-Path $metadataFile -Parent
                if (-not (Test-Path $metaDir)) {
                    New-Item -Path $metaDir -ItemType Directory -Force | Out-Null
                }
                
                # Write metadata
                $metadataContent | Out-File -FilePath $metadataFile -Encoding UTF8 -Force
                
                # Apply multiple protection attributes
                Set-ItemProperty -Path $metadataFile -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System -bor [System.IO.FileAttributes]::ReadOnly)
                
                # Verify file was created and protected
                if (Test-Path $metadataFile) {
                    $successCount++
                    Log-Message "Created protected metadata file: $metadataFile"
                }
            } catch {
                Log-Message "WARNING: Could not create metadata file $metadataFile : $($_.Exception.Message)"
            }
        }
        
        if ($successCount -eq 0) {
            throw "Could not create any metadata files"
        }
        
        Log-Message "SUCCESS: Created $successCount protected metadata files"
        return $true
        
    } catch {
        Log-Message "ERROR: Secure metadata creation failed: $($_.Exception.Message)"
        throw
    }
}

Function Get-TapeMetadataSecure {
    param([string]$DriveLetter = $TapeDrive)
    
    try {
        $tapeDriveRoot = "${DriveLetter}\"
        if (-not (Test-Path -Path $tapeDriveRoot -PathType Container)) {
            throw "Tape drive not accessible"
        }
        
        # Check multiple possible metadata locations
        $possibleMetadataFiles = @(
            Join-Path $tapeDriveRoot "~tape_metadata.dat"
            Join-Path $tapeDriveRoot "SystemVolume\.tapeid" 
            Join-Path $tapeDriveRoot "\.tape_registry"
            Join-Path $tapeDriveRoot ".tape_metadata.xml"  # Legacy location
        )
        
        foreach ($metadataFile in $possibleMetadataFiles) {
            if (Test-Path $metadataFile) {
                try {
                    $content = Get-Content $metadataFile -Raw -ErrorAction Stop
                    $metadata = $content | ConvertFrom-Json
                    
                    # Validate the metadata signature
                    $expectedSignature = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($metadata.UniqueID))).Hash
                    if ($metadata.Signature -eq $expectedSignature) {
                        Log-Message "SUCCESS: Validated metadata from $metadataFile"
                        return $metadata.UniqueID, $metadata.Label, $metadata.TapeNumber
                    } else {
                        Log-Message "WARNING: Metadata signature invalid in $metadataFile"
                    }
                } catch {
                    Log-Message "WARNING: Could not read/parse $metadataFile : $($_.Exception.Message)"
                }
            }
        }
        
        # If no metadata found, check for tape fingerprinting
        Log-Message "No valid metadata files found - attempting tape fingerprinting..."
        return Get-TapeFingerprint -DriveLetter $DriveLetter
        
    } catch {
        Log-Message "ERROR: Secure metadata detection failed: $($_.Exception.Message)"
        throw
    }
}

Function Get-TapeFingerprint {
    param([string]$DriveLetter = $TapeDrive)
    
    try {
        $tapeDriveRoot = "${DriveLetter}\"
        
        # Method 1: Check existing file structure for identification
        $existingFiles = Get-ChildItem -Path $tapeDriveRoot -Recurse -File -ErrorAction SilentlyContinue | 
                        Select-Object -First 100 | Sort-Object Name
        
        if ($existingFiles.Count -gt 0) {
            # Create fingerprint from file structure
            $fingerprintData = ""
            foreach ($file in $existingFiles) {
                $fingerprintData += "$($file.Name)|$($file.Length)|$($file.LastWriteTime.Ticks)|"
            }
            
            $fingerprint = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($fingerprintData)))).Hash
            Log-Message "Created tape fingerprint from file structure: $fingerprint"
            
            # Try to identify tape from database using fingerprint
            $knownTape = Get-TapeFromFingerprint -Fingerprint $fingerprint
            if ($knownTape) {
                Log-Message "IDENTIFIED: Tape $($knownTape.TapeLabel) [$($knownTape.TapeUniqueID)] via fingerprint"
                return $knownTape.TapeUniqueID, $knownTape.TapeLabel, $knownTape.TapeNumber
            }
        }
        
        # Method 2: If no files, check tape capacity and characteristics
        $driveInfo = Get-PSDrive -Name $DriveLetter.TrimEnd(':') -ErrorAction SilentlyContinue
        if ($driveInfo) {
            $capacityHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes("$($driveInfo.Used)|$($driveInfo.Free)")))).Hash
            Log-Message "Created tape fingerprint from capacity: $capacityHash"
        }
        
        # If we can't identify, treat as new tape but log the incident
        Log-Message "WARNING: Could not identify tape - metadata missing and fingerprinting failed"
        Send-MetadataTamperAlert
        return $null, $null, $null
        
    } catch {
        Log-Message "ERROR: Tape fingerprinting failed: $($_.Exception.Message)"
        return $null, $null, $null
    }
}

Function Get-TapeFromFingerprint {
    param([string]$Fingerprint)
    
    try {
        Import-Module PSSQLite -Force
        $query = "SELECT TapeLabel, TapeUniqueID, TapeNumber FROM TapeRegistry WHERE TapeFingerprint = '$Fingerprint'"
        $result = Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        return $result
    } catch {
        Log-Message "WARNING: Fingerprint database lookup failed: $($_.Exception.Message)"
        return $null
    }
}

Function Test-MetadataIntegrity {
    param([string]$DriveLetter = $TapeDrive)
    
    $metadataLocations = @(
        Join-Path $DriveLetter "~tape_metadata.dat"
        Join-Path $DriveLetter "SystemVolume\.tapeid"
        Join-Path $DriveLetter "\.tape_registry"
    )
    
    $validMetadataCount = 0
    foreach ($metadataFile in $metadataLocations) {
        if (Test-Path $metadataFile) {
            try {
                $content = Get-Content $metadataFile -Raw -ErrorAction Stop
                $metadata = $content | ConvertFrom-Json
                
                # Validate signature
                $expectedSignature = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($metadata.UniqueID))).Hash
                if ($metadata.Signature -eq $expectedSignature) {
                    $validMetadataCount++
                }
            } catch {
                # Metadata file exists but corrupted
                Log-Message "WARNING: Corrupted metadata file: $metadataFile"
            }
        }
    }
    
    if ($validMetadataCount -eq 0) {
        Log-Message "CRITICAL: No valid metadata files found - possible tampering"
        Send-MetadataTamperAlert
        return $false
    }
    
    Log-Message "Metadata integrity check: $validMetadataCount valid files found"
    return $true
}

Function Send-MetadataTamperAlert {
    $subject = "CRITICAL: Tape Metadata Tampering Detected"
    $body = @"
TAPE METADATA TAMPERING ALERT

WARNING: Tape metadata files appear to be missing or tampered with.

Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Tape Drive: $TapeDrive
Current Tape: $(if ($script:TapeLabel) { "$script:TapeLabel [$script:TapeUniqueID]" } else { "Unknown" })

POSSIBLE CAUSES:
1. Metadata files accidentally deleted
2. Tape was reformatted
3. Malicious tampering

ACTION REQUIRED:
- Verify tape identity manually
- Check who had access to the tape
- Review tape handling procedures

This is a CRITICAL alert from the Tape Archiving System.
"@
    
    Send-Email -Subject $subject -Body $body
}

# ============================
# TAPE DRIVE MANAGEMENT FUNCTIONS
# ============================
Function Test-TapeDriveAvailable {
    param(
        [int]$RetryCount = $TapeRetryAttempts,
        [int]$RetryDelay = $TapeRetryDelay
    )
    
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            $tapeDriveRoot = "${TapeDrive}\"
            if (Test-Path -Path $tapeDriveRoot -PathType Container) {
                $script:TapeDriveAvailable = $true
                Log-Message "SUCCESS: Tape drive $TapeDrive is available (attempt $attempt/$RetryCount)"
                return $true
            } else {
                Log-Message "Tape drive $TapeDrive not accessible (attempt $attempt/$RetryCount)"
            }
        } catch {
            Log-Message "ERROR: Tape drive check failed (attempt $attempt/$RetryCount): $($_.Exception.Message)"
        }
        
        if ($attempt -lt $RetryCount) {
            Log-Message "Waiting $RetryDelay seconds before retrying tape drive check..."
            Start-Sleep -Seconds $RetryDelay
        }
    }
    
    $script:TapeDriveAvailable = $false
    Log-Message "CRITICAL: Tape drive $TapeDrive unavailable after $RetryCount attempts"
    return $false
}

Function Update-TapeDriveStatus {
    try {
        $tapeDriveRoot = "${TapeDrive}\"
        $wasAvailable = $script:TapeDriveAvailable
        $script:TapeDriveAvailable = Test-Path -Path $tapeDriveRoot -PathType Container
        
        if ($wasAvailable -and -not $script:TapeDriveAvailable) {
            Log-Message "TAPE DRIVE STATUS: Became unavailable (tape likely removed)"
        } elseif (-not $wasAvailable -and $script:TapeDriveAvailable) {
            Log-Message "TAPE DRIVE STATUS: Became available (tape likely inserted)"
        }
        
        return $script:TapeDriveAvailable
    } catch {
        Log-Message "ERROR: Tape drive status update failed: $($_.Exception.Message)"
        $script:TapeDriveAvailable = $false
        return $false
    }
}

Function Get-TapeUniqueIDWithDetection {
    param([string]$DriveLetter = $TapeDrive)
    
    try {
        Log-Message "Starting secure tape detection..."
        
        # First check metadata integrity
        if (-not (Test-MetadataIntegrity -DriveLetter $DriveLetter)) {
            Log-Message "Metadata integrity check failed - using fingerprinting"
            $tapeResult = Get-TapeFingerprint -DriveLetter $DriveLetter
            if ($tapeResult[0]) {
                return $tapeResult
            }
            # If fingerprinting also fails, create new metadata
        }
        
        # Try to read existing metadata
        $metadataResult = Get-TapeMetadataSecure -DriveLetter $DriveLetter
        if ($metadataResult[0]) {
            Log-Message "Existing tape identified via secure metadata: $($metadataResult[1]) [$($metadataResult[0])]"
            return $metadataResult
        }
        
        # Create new secure metadata
        Log-Message "No existing tape identified - creating new secure metadata"
        $nextTapeNumber = Get-NextTapeNumber
        $tapeUniqueID = "LTO-9 $($nextTapeNumber.ToString('0000'))"
        $tapeLabel = "LTO-9"
        
        New-SecureTapeMetadata -DriveLetter $DriveLetter -TapeUniqueID $tapeUniqueID -TapeLabel $tapeLabel -TapeNumber $nextTapeNumber
        Store-TapeInDatabase -TapeLabel $tapeLabel -TapeUniqueID $tapeUniqueID -TapeFingerprint $tapeUniqueID
        
        Log-Message "New tape registered with secure metadata: $tapeLabel [$tapeUniqueID]"
        return $tapeUniqueID, $tapeLabel
        
    } catch {
        Log-Message "ERROR: Secure tape detection failed: $($_.Exception.Message)"
        throw
    }
}

Function Get-TapeFreeSpace {
    param(
        [string]$DriveLetter = $TapeDrive,
        [int]$RetryCount = $TapeRetryAttempts,
        [int]$RetryDelay = $TapeRetryDelay
    )
    
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            $tapeDriveRoot = "${DriveLetter}\"
            if (-not (Test-Path -Path $tapeDriveRoot -PathType Container)) {
                throw "Tape drive not accessible"
            }
            
            $driveInfo = Get-PSDrive -Name $DriveLetter.TrimEnd(':') -ErrorAction Stop
            $freeSpaceBytes = $driveInfo.Free
            $totalSizeBytes = $driveInfo.Used + $driveInfo.Free
            
            Log-Message "Tape space check successful (attempt $attempt) - Total: $([Math]::Round($totalSizeBytes/1GB,2)) GB, Free: $([Math]::Round($freeSpaceBytes/1GB,2)) GB"
            
            return $freeSpaceBytes
        } catch {
            Log-Message "ERROR: Tape free space check failed (attempt $attempt/$RetryCount): $($_.Exception.Message)"
            
            if ($attempt -lt $RetryCount) {
                Log-Message "Waiting $RetryDelay seconds before retrying space check..."
                Start-Sleep -Seconds $RetryDelay
            } else {
                Log-Message "CRITICAL: Unable to determine tape free space after $RetryCount attempts"
                return 0
            }
        }
    }
}

Function Test-TapeFull {
    param(
        [long]$RequiredSpace = 0,
        [string]$DriveLetter = $TapeDrive
    )
    
    try {
        $freeSpace = Get-TapeFreeSpace -DriveLetter $DriveLetter
        $requiredSpaceWithBuffer = $RequiredSpace + $TapeFullThreshold
        
        Log-Message "TAPE FULL CHECK:"
        Log-Message "  - Free space: $([Math]::Round($freeSpace/1GB,2)) GB"
        Log-Message "  - Required (with buffer): $([Math]::Round($requiredSpaceWithBuffer/1GB,2)) GB"
        Log-Message "  - Will fit: $($requiredSpaceWithBuffer -le $freeSpace)"
        
        $isFull = $requiredSpaceWithBuffer -gt $freeSpace
        
        if ($isFull) {
            Log-Message "TAPE FULL CONDITION: Insufficient space for operation with safety buffer"
        }
        
        return $isFull
    } catch {
        Log-Message "ERROR: Tape full check failed: $($_.Exception.Message)"
        # If we can't determine space, assume tape might be full to be safe
        return $true
    }
}

Function Test-TapeActuallyChanged {
    param(
        [string]$previousTapeUniqueID,
        [string]$currentTapeUniqueID,
        [string]$driveLetter = $TapeDrive
    )
    
    try {
        # If IDs are different, definitely changed
        if ($previousTapeUniqueID -ne $currentTapeUniqueID) {
            Log-Message "Tape change confirmed: $previousTapeUniqueID -> $currentTapeUniqueID"
            return $true
        }
        
        # Same ID - check if tape was actually physically removed
        Log-Message "Same tape ID detected - checking if tape was physically swapped..."
        
        # Method 1: Check if drive was completely unavailable for a period
        if (-not $script:TapeDriveAvailable) {
            Log-Message "Drive was unavailable - assuming physical tape change"
            return $true
        }
        
        # Method 2: Check metadata file creation time (if reinserted, it might be newer)
        $metadataFile = Join-Path $driveLetter "~tape_metadata.dat"
        if (Test-Path $metadataFile) {
            $fileInfo = Get-Item $metadataFile
            $timeSinceLastCheck = (Get-Date) - $fileInfo.LastWriteTime
            if ($timeSinceLastCheck.TotalMinutes -lt 5) {
                Log-Message "Metadata file recently accessed - likely same physical tape"
                return $false
            }
        }
        
        # Method 3: If we get here and IDs match, it's probably the same tape
        Log-Message "Same physical tape confirmed: $currentTapeUniqueID"
        return $false
        
    } catch {
        Log-Message "ERROR: Tape change detection failed: $($_.Exception.Message)"
        # When in doubt, assume same tape to avoid false positives
        return $false
    }
}

# ============================
# TAPE SWAP AND NOTIFICATION FUNCTIONS
# ============================
Function Wait-TapeDriveAvailable {
    param(
        [int]$MaxWaitMinutes = 120,  # 2 hour maximum wait
        [int]$CheckInterval = 30     # Check every 30 seconds as requested
    )
    
    $startTime = Get-Date
    $lastNotificationTime = $null
    $notificationInterval = 600  # Send notification every 10 minutes
    
    Log-Message "Starting tape drive monitoring - Maximum wait: $MaxWaitMinutes minutes, Check interval: $CheckInterval seconds"
    
    while ($true) {
        $elapsedTime = (Get-Date) - $startTime
        $totalSeconds = [math]::Round($elapsedTime.TotalSeconds)
        $totalMinutes = [math]::Round($elapsedTime.TotalMinutes)
        
        # Check for timeout
        if ($totalMinutes -ge $MaxWaitMinutes) {
            $err = "Tape drive wait timeout after $totalMinutes minutes"
            Log-Message "CRITICAL: $err"
            Send-TapeSwapNotification -type "timeout" -waitTime $totalSeconds -tapeLabel $script:TapeLabel
            throw $err
        }
        
        # Send periodic notifications
        if ($lastNotificationTime -eq $null -or ($totalSeconds - $lastNotificationTime) -ge $notificationInterval) {
            if ($totalMinutes -eq 0) {
                Send-TapeSwapNotification -type "unmounted" -waitTime $totalSeconds -tapeLabel $script:TapeLabel
            } else {
                Send-TapeSwapNotification -type "reminder" -waitTime $totalSeconds -tapeLabel $script:TapeLabel
            }
            $lastNotificationTime = $totalSeconds
        }
        
        # Check if tape drive is available
        if (Test-TapeDriveAvailable -RetryCount 1 -RetryDelay 5) {
            Log-Message "SUCCESS: Tape drive became available after $totalMinutes minutes $($totalSeconds % 60) seconds"
            
            # Additional stabilization time
            Log-Message "Allowing tape drive to stabilize..."
            Start-Sleep -Seconds 10
            
            return $true
        }
        
        # Wait before next check
        Log-Message "Tape drive still unavailable. Waiting $CheckInterval seconds... (Elapsed: $totalMinutes minutes)"
        Start-Sleep -Seconds $CheckInterval
    }
}

Function Invoke-TapeSwap {
    param([string]$currentTapeLabel, [string]$currentTapeUniqueID)
    
    Log-Message "=== INITIATING ROBUST TAPE SWAP PROCESS ==="
    Log-Message "Current tape: $currentTapeLabel [$currentTapeUniqueID]"
    
    # Store the previous tape information BEFORE updating
    $script:PreviousTapeLabel = $currentTapeLabel
    $script:PreviousTapeUniqueID = $currentTapeUniqueID
    $script:CurrentTapeSwapAttempt++
    
    # Send initial tape full notification
    $freeSpace = Get-TapeFreeSpace
    Send-TapeFullEmail -tapeLabel $currentTapeLabel -tapeUniqueID $currentTapeUniqueID -freeSpace $freeSpace -previousTapeLabel $script:PreviousTapeLabel
    $script:EmailSentForCurrentTape = $true
    
    try {
        # Wait for tape drive to become available (new tape inserted)
        Log-Message "Waiting for new tape insertion..."
        Wait-TapeDriveAvailable
        
        # Detect the new tape
        Log-Message "Detecting new tape..."
        $newTapeResult = Get-TapeUniqueIDWithDetection -DriveLetter $TapeDrive
        $newTapeUniqueID = $newTapeResult[0]
        $newTapeLabel = $newTapeResult[1]
        
        # Check if it's actually the same physical tape or a new one with same ID
        $tapeActuallyChanged = Test-TapeActuallyChanged -previousTapeUniqueID $currentTapeUniqueID -currentTapeUniqueID $newTapeUniqueID

        if (-not $tapeActuallyChanged) {
            Log-Message "WARNING: Same physical tape reinserted: $newTapeLabel [$newTapeUniqueID]"
            Send-TapeSwapNotification -type "same_tape" -waitTime 0 -tapeLabel $currentTapeLabel
            
            # Check if this tape now has enough space
            $freeSpace = Get-TapeFreeSpace
            if ($freeSpace -gt $TapeFullThreshold) {
                Log-Message "Same tape now has sufficient space ($([Math]::Round($freeSpace/1GB,2)) GB), continuing..."
                $script:TapeUniqueID = $newTapeUniqueID
                $script:TapeLabel = $newTapeLabel
                return $true
            } else {
                Log-Message "Same tape still insufficient space ($([Math]::Round($freeSpace/1GB,2)) GB), requesting new tape..."
                # Recursively call tape swap again
                return Invoke-TapeSwap -currentTapeLabel $currentTapeLabel -currentTapeUniqueID $currentTapeUniqueID
            }
        } else {
            # New tape detected!
            Log-Message "SUCCESS: New tape detected: $newTapeLabel [$newTapeUniqueID]"
            
            # Verify new tape has sufficient space
            $freeSpace = Get-TapeFreeSpace
            if ($freeSpace -gt $TapeFullThreshold) {
                Log-Message "New tape has sufficient space: $([Math]::Round($freeSpace/1GB,2)) GB"
                
                # Send success notification with proper previous tape info
                Send-TapeSwapNotification -type "success" -waitTime 0 -tapeLabel $newTapeLabel -newTapeID $newTapeUniqueID -previousTapeLabel $script:PreviousTapeLabel
                
                # Update current tape info
                $script:TapeUniqueID = $newTapeUniqueID
                $script:TapeLabel = $newTapeLabel
                $script:EmailSentForCurrentTape = $false
                $script:CurrentTapeSwapAttempt = 0
                
                Log-Message "Tape swap completed: Previous=$script:PreviousTapeLabel, Current=$script:TapeLabel"
                return $true
            } else {
                Log-Message "WARNING: New tape has insufficient space ($([Math]::Round($freeSpace/1GB,2)) GB), requesting different tape"
                Send-TapeSwapNotification -type "same_tape" -waitTime 0 -tapeLabel $newTapeLabel
                # Recursively call tape swap again
                return Invoke-TapeSwap -currentTapeLabel $currentTapeLabel -currentTapeUniqueID $currentTapeUniqueID
            }
        }
    } catch {
        $err = "Tape swap process failed: $($_.Exception.Message)"
        Log-Message "CRITICAL: $err"
        throw $err
    }
}

Function Send-TapeFullEmail {
    param(
        $tapeLabel, 
        $tapeUniqueID, 
        $freeSpace,
        $previousTapeLabel = $null
    )
    
    $subject = "TAPE FULL: $tapeLabel [$tapeUniqueID] - Insert New Tape"
    
    # Build the body with conditional previous tape information
    $body = @"
TAPE STORAGE FULL ALERT

Current Tape Details:
- Tape Label: $tapeLabel
- Tape Unique ID: $tapeUniqueID
- Remaining Free Space: $([Math]::Round($freeSpace/1GB,2)) GB
"@

    # Add previous tape information if available
    if ($previousTapeLabel) {
        $body += @"

Previous Tape: $previousTapeLabel
"@
    }

    $body += @"

ACTION REQUIRED:
Please insert a new formatted tape into the drive. The system will automatically:
1. Detect the new tape
2. Generate a new sequential tape ID
3. Continue archiving where it left off

Next tape in sequence will be automatically numbered.

This is an automated message from the Tape Archiving System.
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@

    Send-Email -Subject $subject -Body $body
}

Function Send-TapeSwapNotification {
    param(
        [string]$type,  # unmounted, reminder, success, same_tape, timeout
        [int]$waitTime,
        [string]$tapeLabel,
        [string]$newTapeID = $null,
        [string]$previousTapeLabel = $null
    )
    
    $minutesWaited = [math]::Floor($waitTime / 60)
    
    switch ($type) {
        "unmounted" {
            $subject = "Tape Drive Unmounted - Awaiting New Tape"
            $body = @"
TAPE SWAP IN PROGRESS

The tape drive $TapeDrive has been unmounted for tape removal.

Previous Tape: $tapeLabel
Action Required: Please insert a new formatted tape

The script is monitoring every 30 seconds for the new tape.
Wait time so far: $minutesWaited minutes

This is an automated notification from the Tape Archiving System.
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        }
        "reminder" {
            $subject = "Reminder: Still Waiting for New Tape Insertion"
            $body = @"
TAPE SWAP REMINDER

Still waiting for new tape insertion on drive $TapeDrive.

Previous Tape: $tapeLabel
Wait time: $minutesWaited minutes

The script continues to monitor every 30 seconds for the new tape.

This is an automated reminder from the Tape Archiving System.
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        }
        "success" {
            $subject = "New Tape Detected and Verified Successfully"
            $body = @"
NEW TAPE DETECTED SUCCESSFULLY

New tape has been detected and verified on drive $TapeDrive.

Previous Tape: $previousTapeLabel
New Tape: $newTapeID
Total wait time: $minutesWaited minutes

The archiving process has resumed automatically.

This is an automated notification from the Tape Archiving System.
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        }
        "same_tape" {
            $subject = "Warning: Same Tape Reinserted"
            $body = @"
SAME TAPE REINSERTED WARNING

The same tape has been reinserted into drive $TapeDrive.

Tape: $tapeLabel
Wait time: $minutesWaited minutes

The script is still waiting for a NEW tape with sufficient space.
Please insert a different, formatted tape.

This is an automated warning from the Tape Archiving System.
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        }
        "timeout" {
            $subject = "CRITICAL: Tape Swap Timeout - Manual Intervention Required"
            $body = @"
TAPE SWAP TIMEOUT ALERT

The script has been waiting for a new tape for $minutesWaited minutes.

Drive: $TapeDrive
Previous Tape: $tapeLabel

The script has stopped waiting and requires manual intervention.
Please check the tape drive and restart the archiving process.

This is a CRITICAL alert from the Tape Archiving System.
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        }
    }
    
    Send-Email -Subject $subject -Body $body
}

# ============================
# TAPE REGISTRY FUNCTIONS
# ============================
Function Get-TapeFromDatabase {
    param([string]$TapeFingerprint)
    
    try {
        Import-Module PSSQLite -Force
        
        # Check for existing tape
        $query = "SELECT TapeLabel, TapeUniqueID, TapeNumber FROM TapeRegistry WHERE TapeFingerprint = '$TapeFingerprint'"
        $result = Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        
        if ($result) {
            # Update last seen timestamp
            $updateQuery = "UPDATE TapeRegistry SET LastSeen = CURRENT_TIMESTAMP WHERE TapeFingerprint = '$TapeFingerprint'"
            Invoke-SqliteQuery -Query $updateQuery -DataSource $DatabasePath
            return $result
        }
        
        return $null
    } catch {
        Log-Message "WARNING: Could not check tape database: $($_.Exception.Message)"
        return $null
    }
}

Function Store-TapeInDatabase {
    param([string]$TapeLabel, [string]$TapeUniqueID, [string]$TapeFingerprint)
    
    try {
        Import-Module PSSQLite -Force
        
        $query = @"
INSERT INTO TapeRegistry (TapeLabel, TapeUniqueID, TapeFingerprint, FirstSeen, LastSeen)
VALUES ('$TapeLabel', '$TapeUniqueID', '$TapeFingerprint', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
"@
        Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        Log-Message "Stored new tape in registry: $TapeLabel [$TapeUniqueID]"
    } catch {
        Log-Message "WARNING: Could not store tape in database: $($_.Exception.Message)"
    }
}

Function Get-NextTapeNumber {
    try {
        Import-Module PSSQLite -Force
        
        # Get the highest tape number from existing tapes in the database
        $query = "SELECT TapeUniqueID, TapeNumber FROM TapeRegistry WHERE TapeUniqueID LIKE 'LTO-9 %'"
        $existingTapes = Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        
        $maxNumber = 0
        foreach ($tape in $existingTapes) {
            if ($tape.TapeNumber -and $tape.TapeNumber -gt $maxNumber) {
                $maxNumber = $tape.TapeNumber
            } elseif ($tape.TapeUniqueID -match 'LTO-9 (\d+)') {
                $number = [int]$matches[1]
                if ($number -gt $maxNumber) {
                    $maxNumber = $number
                }
            }
        }
        
        # Also check metadata files on currently mounted tapes
        try {
            $tapeDriveRoot = "${TapeDrive}\"
            if (Test-Path -Path $tapeDriveRoot -PathType Container) {
                $metadataResult = Get-TapeMetadataSecure -DriveLetter $TapeDrive
                if ($metadataResult[2]) {
                    $currentNumber = [int]$metadataResult[2]
                    if ($currentNumber -gt $maxNumber) {
                        $maxNumber = $currentNumber
                    }
                }
            }
        } catch {
            # Ignore errors reading current tape metadata
        }
        
        $nextNumber = $maxNumber + 1
        Log-Message "Next available tape number: $nextNumber (max found: $maxNumber)"
        return $nextNumber
        
    } catch {
        Log-Message "WARNING: Could not determine next tape number from database. Starting from 1."
        return 1
    }
}

# ============================
# SOURCE CLEANUP FUNCTIONS
# ============================
Function Remove-SourceFolderSafely {
    param(
        [string]$SourcePath,
        [string]$TapePath,
        [string]$FolderHash
    )
    
    try {
        Log-Message "=== INITIATING SOURCE CLEANUP: $SourcePath ==="
        
        # Step 1: Verify the folder still exists
        if (-not (Test-Path $SourcePath -PathType Container)) {
            Log-Message "SKIP: Source folder already deleted: $SourcePath"
            return $true, "Already deleted"
        }
        
        # Step 2: Re-verify the folder hash matches what was archived
        Log-Message "Re-verifying folder integrity before deletion..."
        $currentHash = Get-FolderHash -FolderPath $SourcePath
        if ($currentHash -ne $FolderHash) {
            $err = "Folder hash mismatch! Source may have changed since archiving. Current: $currentHash, Archived: $FolderHash"
            Log-Message "ERROR: $err"
            return $false, $err
        }
        
        # Step 3: Verify tape copy exists and is accessible
        Log-Message "Verifying tape copy exists: $TapePath"
        if (-not (Test-Path $TapePath -PathType Container)) {
            $err = "Tape copy verification failed: $TapePath not found"
            Log-Message "ERROR: $err"
            return $false, $err
        }
        
        # Step 4: Quick file count comparison
        $sourceFileCount = (Get-ChildItem $SourcePath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
        $tapeFileCount = (Get-ChildItem $TapePath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
        
        if ($sourceFileCount -ne $tapeFileCount) {
            $err = "File count mismatch! Source: $sourceFileCount files, Tape: $tapeFileCount files"
            Log-Message "ERROR: $err"
            return $false, $err
        }
        
        Log-Message "Verification passed - Source: $sourceFileCount files, Tape: $tapeFileCount files"
        
        # Step 5: Create backup log of what's being deleted
        $deletionLog = @"
SOURCE FOLDER DELETION LOG
==========================
Source Path: $SourcePath
Tape Path: $TapePath
Folder Hash: $FolderHash
File Count: $sourceFileCount
Deletion Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Verified By: Tape Archiving System
"@
        
        $logPath = Join-Path (Split-Path $LogFile -Parent) "DeletionLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $deletionLog | Out-File -FilePath $logPath -Encoding UTF8
        Log-Message "Deletion log created: $logPath"
        
        # Step 6: Perform the deletion
        Log-Message "Starting safe deletion of source folder..."
        
        # Method 1: Try standard deletion first
        try {
            Remove-Item -Path $SourcePath -Recurse -Force -ErrorAction Stop
            Log-Message "SUCCESS: Standard deletion completed"
        } catch {
            Log-Message "WARNING: Standard deletion failed, attempting robocopy purge method: $($_.Exception.Message)"
            
            # Method 2: Robocopy purge (more aggressive)
            & robocopy.exe "C:\EmptyDir" "$SourcePath" /PURGE /MIR /NJH /NJS /NP /R:1 /W:1 | Out-Null
            if (Test-Path $SourcePath) {
                $err = "All deletion methods failed for: $SourcePath"
                Log-Message "ERROR: $err"
                return $false, $err
            }
            Log-Message "SUCCESS: Robocopy purge deletion completed"
        }
        
        # Step 7: Verify deletion was successful
        if (Test-Path $SourcePath) {
            $err = "Deletion verification failed - folder still exists: $SourcePath"
            Log-Message "ERROR: $err"
            return $false, $err
        }
        
        Log-Message "SUCCESS: Source folder deleted and verified: $SourcePath"
        
        # Step 8: Update database
        Update-SourceDeletionStatus -SourcePath $SourcePath -FolderHash $FolderHash
        
        return $true, "Successfully deleted and verified"
        
    } catch {
        $err = "Source deletion process failed: $($_.Exception.Message)"
        Log-Message "ERROR: $err"
        return $false, $err
    }
}

Function Update-SourceDeletionStatus {
    param(
        [string]$SourcePath,
        [string]$FolderHash
    )
    
    try {
        Import-Module PSSQLite -Force
        
        $e = [System.Security.SecurityElement]
        $src = $e::Escape($SourcePath)
        $hsh = $e::Escape($FolderHash)
        $deletionDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        
        $query = @"
UPDATE $DatabaseTable 
SET SourceDeleted = 1, SourceDeletedDate = '$deletionDate'
WHERE SourcePath = '$src' AND FolderHash = '$hsh' AND Status = 'SUCCESS'
"@
        
        $result = Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        Log-Message "Database updated: Source deletion recorded for $SourcePath"
        
    } catch {
        Log-Message "WARNING: Could not update database deletion status: $($_.Exception.Message)"
    }
}

Function Send-SpaceRecoveryNotification {
    param(
        [string]$FolderPath,
        [double]$SpaceGB,
        [string]$TapeID
    )
    
    $subject = "Source Cleanup Completed: $([Math]::Round($SpaceGB, 2)) GB Recovered"
    $body = @"
SOURCE CLEANUP SUCCESS

Successfully archived and cleaned up source folder:

Folder: $FolderPath
Space Recovered: $SpaceGB GB
Tape: $TapeID
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

The folder has been:
✓ Successfully archived to tape
✓ Verified against tape copy
✓ Safely deleted from source
✓ Logged in database

This is an automated notification from the Tape Archiving System.
"@
    
    Send-Email -Subject $subject -Body $body
}

Function Send-CleanupFailureAlert {
    param(
        [string]$FolderPath,
        [string]$ErrorMessage
    )
    
    $subject = "WARNING: Source Cleanup Failed - Manual Intervention Required"
    $body = @"
SOURCE CLEANUP FAILURE

Failed to delete source folder after successful archiving:

Folder: $FolderPath
Error: $ErrorMessage
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

STATUS:
✓ Folder successfully archived to tape
✗ Source folder deletion failed

ACTION REQUIRED:
- Investigate the source folder
- Check file permissions/locks
- Manually delete if appropriate

This is an automated alert from the Tape Archiving System.
"@
    
    Send-Email -Subject $subject -Body $body
}

Function Invoke-CleanupVerification {
    param(
        [string]$Server,
        [switch]$WhatIf
    )
    
    try {
        Log-Message "=== CLEANUP VERIFICATION TOOL ==="
        Log-Message "Server: $Server"
        Log-Message "WhatIf Mode: $WhatIf"
        
        Import-Module PSSQLite -Force
        
        # Get all successfully archived but not deleted folders
        $query = @"
SELECT SourcePath, TapeLabel, TapeUniqueID, FolderHash, SizeBytes, ArchiveDate
FROM $DatabaseTable 
WHERE ServerName = '$Server' 
AND Status = 'SUCCESS' 
AND SourceDeleted = 0
AND SourcePath LIKE '$Server%'
"@
        
        $pendingCleanup = Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
        
        if ($pendingCleanup.Count -eq 0) {
            Log-Message "No pending cleanup found for server $Server"
            return
        }
        
        Log-Message "Found $($pendingCleanup.Count) folders pending cleanup"
        
        $totalSpaceGB = 0
        $processedCount = 0
        
        foreach ($folder in $pendingCleanup) {
            Log-Message "Processing: $($folder.SourcePath)"
            
            if (Test-Path $folder.SourcePath -PathType Container) {
                Log-Message "Folder still exists - initiating cleanup..."
                $spaceGB = [Math]::Round($folder.SizeBytes / 1GB, 2)
                $totalSpaceGB += $spaceGB
                
                if (-not $WhatIf) {
                    $destinationPath = Join-Path -Path $TapeDrive -ChildPath (Split-Path $folder.SourcePath -Leaf)
                    $success, $message = Remove-SourceFolderSafely -SourcePath $folder.SourcePath -TapePath $destinationPath -FolderHash $folder.FolderHash
                    
                    if ($success) {
                        $processedCount++
                        Log-Message "SUCCESS: Cleanup completed - recovered $spaceGB GB"
                    } else {
                        Log-Message "FAILED: $message"
                    }
                } else {
                    Log-Message "WHATIF: Would delete $($folder.SourcePath) - $spaceGB GB"
                    $processedCount++
                }
            } else {
                Log-Message "Folder already deleted - updating database"
                if (-not $WhatIf) {
                    Update-SourceDeletionStatus -SourcePath $folder.SourcePath -FolderHash $folder.FolderHash
                }
            }
        }
        
        Log-Message "=== CLEANUP VERIFICATION COMPLETE ==="
        Log-Message "Total space recoverable: $totalSpaceGB GB"
        Log-Message "Folders processed: $processedCount"
        
    } catch {
        Log-Message "ERROR: Cleanup verification failed: $($_.Exception.Message)"
    }
}

# ============================
# DUAL TAPE FUNCTIONS (FUTURE IMPLEMENTATION)
# ============================
<#
Function Initialize-DualTapeSystem {
    if (-not $EnableDualTape) {
        return $false
    }
    
    try {
        Log-Message "Initializing dual tape backup system..."
        
        # Initialize second tape drive
        if (Test-TapeDriveAvailable -DriveLetter $TapeDrive2) {
            $tapeResult2 = Get-TapeUniqueIDWithDetection -DriveLetter $TapeDrive2
            $script:TapeUniqueID2 = $tapeResult2[0]
            $script:TapeLabel2 = $tapeResult2[1]
            $script:TapeDrive2Available = $true
            Log-Message "Secondary tape drive initialized: $script:TapeLabel2 [$script:TapeUniqueID2]"
            return $true
        } else {
            Log-Message "WARNING: Secondary tape drive $TapeDrive2 not available"
            return $false
        }
    } catch {
        Log-Message "ERROR: Dual tape initialization failed: $($_.Exception.Message)"
        return $false
    }
}

Function Copy-ToSecondaryTape {
    param(
        [string]$SourcePath,
        [string]$FolderName
    )
    
    if (-not $EnableDualTape -or -not $script:TapeDrive2Available) {
        return $false
    }
    
    try {
        $destinationPath2 = Join-Path -Path $TapeDrive2 -ChildPath $FolderName
        Log-Message "Copying to secondary tape: $destinationPath2"
        
        & robocopy.exe "$SourcePath" "$destinationPath2" /MIR /Z /J /R:3 /W:5 /NP /LOG+:$LogFile
        if ($LASTEXITCODE -lt 8) {
            Log-Message "SUCCESS: Secondary tape copy completed for $FolderName"
            return $true
        } else {
            Log-Message "WARNING: Secondary tape copy failed with exit code $LASTEXITCODE"
            return $false
        }
    } catch {
        Log-Message "ERROR: Secondary tape copy failed: $($_.Exception.Message)"
        return $false
    }
}
#>

# ============================
# VALIDATION AND UTILITY FUNCTIONS
# ============================
Function Test-Robocopy {
    try { $rc = Get-Command "robocopy.exe" -ErrorAction Stop; Log-Message "Robocopy: $($rc.Source)"; return $true }
    catch { Log-Message "ERROR: Robocopy not present"; Send-Email -Subject "Tape Archive Error: Robocopy Missing" -Body "Robocopy required"; return $false }
}

Function Test-FolderOlderThanDays { 
    param([System.IO.DirectoryInfo]$Folder, [int]$Days)
    $cutoff = (Get-Date).AddDays(-$Days)
    $isOlder = $Folder.LastWriteTime -lt $cutoff
    Log-Message "Folder $($Folder.FullName) last write: $($Folder.LastWriteTime) cutoff: $cutoff older:$isOlder"
    return $isOlder
}

Function Test-DatabaseConnection {
    try {
        if (Test-Path $DatabasePath) { Log-Message "DB file exists: $DatabasePath"; return $true }
        else { Log-Message "DB file not found (will be created): $DatabasePath"; return $true }
    } catch {
        Log-Message "ERROR: DB connection test failed: $($_.Exception.Message)"
        Send-Email -Subject "Tape Archive Error: DB Connection Failed" -Body $($_.Exception.Message) -IsError $true
        return $false
    }
}

Function Check-JobDuration {
    $elapsedHours = ((Get-Date) - $ScriptStartTime).TotalHours
    if ($elapsedHours -ge $MaxJobDurationHours -and -not $script:JobTimeoutAlertSent) {
        $subject = "Tape Archive Job Running Too Long: $([Math]::Round($elapsedHours,1)) hours"
        $body = @"
Tape Archive Job Duration Alert

The tape archiving job has been running for $([Math]::Round($elapsedHours, 1)) hours,
which exceeds the configured threshold of $MaxJobDurationHours hours.

Start: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
Now:   $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))

Please review the job and logs.
"@
        Send-Email -Subject $subject -Body $body
        $script:JobTimeoutAlertSent = $true
        Log-Message "Job duration alert sent."
    }
}

# ============================
# MAIN PROCESSING FUNCTION
# ============================
Function Process-Server {
    param([string]$Server)
    $SourceDir = Join-Path $Server $SourceBasePath
    Log-Message "=== Processing server: $Server ==="
    Log-Message "Source directory: $SourceDir"

    if (-not (Test-NetworkPath -Path $SourceDir)) {
        $err = "Source $SourceDir unreachable after $NetworkRetries attempts."
        Log-Message "WARNING: $err"
        Log-Message "VALIDATION FAILED: $SourceDir - $err"
        
        # Add to failed servers list
        $script:FailedServers += "$Server - Network unreachable after $NetworkRetries attempts"
        return
    }

    try {
        $folders = Get-ChildItem -Path $SourceDir -Directory -ErrorAction Stop
        Log-Message "Found $($folders.Count) folders on $Server"
        
        # If we get here, server was processed successfully (at least connected)
        $script:ProcessedServers += $Server
        
    } catch {
        $err = "Could not list directories: $($_.Exception.Message)"
        Log-Message "ERROR: $err"
        Log-Message "FOLDER LISTING FAILED: $SourceDir - $err"
        $script:FailedServers += "$Server - $err"
        Send-Email -Subject "Tape Archive Error: Folder Listing Failed on $Server" -Body $err -IsError $true
        return
    }

    foreach ($folder in $folders) {
        # periodic job duration checks
        if ($folders.Count -gt 2 -and ($folder.Name -in @($folders[0].Name, $folders[[math]::Floor($folders.Count/2)].Name, $folders[-1].Name))) { Check-JobDuration }
        Log-Message "--- Evaluating folder: $($folder.FullName) ---"

        if (-not (Test-FolderOlderThanDays -Folder $folder -Days $DaysThreshold)) {
            Log-Message "Skipping (not old enough): $($folder.FullName)"
            continue
        }

        # compute folder hash and check duplication
        try {
            $folderHash = Get-FolderHash -FolderPath $folder.FullName
            if (Test-FolderAlreadyArchived -FolderPath $folder.FullName -FolderHash $folderHash) {
                Log-Message "SKIPPED ALREADY ARCHIVED: $($folder.FullName)"
                continue
            }
        } catch {
            $err = "Hash calculation failed: $($_.Exception.Message)"
            Log-Message "ERROR: $err"
            Log-Message "HASH CALCULATION FAILED: $($folder.FullName) - $err"
            Send-Email -Subject "Tape Archive Error: Hash Failed on $Server" -Body $err -IsError $true
            continue
        }

        # size
        try {
            $folderSize = (Get-ChildItem $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum
            if (-not $folderSize) { $folderSize = 0 }
            Log-Message "Folder size: $([Math]::Round($folderSize/1GB,2)) GB"
        } catch {
            $err = "Size calc failed: $($_.Exception.Message)"
            Log-Message "ERROR: $err"
            Log-Message "SIZE CALCULATION FAILED: $($folder.FullName) - $err"
            continue
        }

        # ENHANCED: Check tape space with robust error handling
        if (Test-TapeFull -RequiredSpace $folderSize) {
            Log-Message "*** TAPE FULL CONDITION TRIGGERED ***"
            Log-Message "WARNING: Tape $($script:TapeLabel) [$($script:TapeUniqueID)] has insufficient space for $($folder.Name)."
            
            if (-not $script:EmailSentForCurrentTape) {
                Log-Message "Sending tape full email alert..."
                $freeSpace = Get-TapeFreeSpace
                Send-TapeFullEmail -tapeLabel $script:TapeLabel -tapeUniqueID $script:TapeUniqueID -freeSpace $freeSpace -previousTapeLabel $script:PreviousTapeLabel
                $script:EmailSentForCurrentTape = $true
                Log-Message "TAPE FULL ALERT SENT: $($script:TapeLabel) [$($script:TapeUniqueID)]"
            }

            Write-Host "`n*** TAPE STORAGE FULL ***" -ForegroundColor Red
            Write-Host "Current Tape: $($script:TapeLabel) [$($script:TapeUniqueID)]" -ForegroundColor Yellow
            Write-Host "Free Space: $([Math]::Round($freeSpace/1GB,2)) GB" -ForegroundColor Yellow
            Write-Host "Next Folder Requires (with buffer): $([Math]::Round(($folderSize + $TapeFullThreshold)/1GB,2)) GB" -ForegroundColor Yellow
            Write-Host "`nPlease insert a new formatted tape and ensure it is mounted as $TapeDrive" -ForegroundColor Green
            Write-Host "Script will automatically detect when the new tape is ready..." -ForegroundColor Green
            Write-Host "Monitoring every 30 seconds for new tape insertion..." -ForegroundColor Cyan
            
            # Use the new robust tape swap function
            try {
                # Store current tape info before swap
                $currentTapeBeforeSwap = $script:TapeLabel
                $currentTapeIDBeforeSwap = $script:TapeUniqueID
                
                Invoke-TapeSwap -currentTapeLabel $script:TapeLabel -currentTapeUniqueID $script:TapeUniqueID
                Log-Message "Tape swap completed: $currentTapeBeforeSwap -> $($script:TapeLabel)"
            } catch {
                $err = "Tape swap failed: $($_.Exception.Message)"
                Log-Message "CRITICAL: $err"
                throw $err
            }
        }

        # destination and robocopy
        $destinationPath = Join-Path -Path $TapeDrive -ChildPath $folder.Name
        Log-Message "Starting Robocopy: $($folder.FullName) -> $destinationPath"
        try {
            & robocopy.exe "$($folder.FullName)" "$destinationPath" /MIR /Z /J /R:3 /W:5 /NP /LOG+:$LogFile
            if ($LASTEXITCODE -lt 8) {
                Log-Message "SUCCESS: Robocopy finished for $($folder.Name) (Exit $LASTEXITCODE)"
                $fileCount = (Get-ChildItem $folder.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
                
                # Write to database first
                Write-DatabaseLog -SourcePath $folder.FullName -TapeLabel $script:TapeLabel -TapeUniqueID $script:TapeUniqueID -SizeBytes $folderSize -FolderHash $folderHash -Status "SUCCESS" -FileCount $fileCount -ServerName $Server
                
                # Now safely delete the source folder
                $deleteSuccess, $deleteMessage = Remove-SourceFolderSafely -SourcePath $folder.FullName -TapePath $destinationPath -FolderHash $folderHash
                
                if ($deleteSuccess) {
                    Log-Message "SUCCESS: Source cleanup completed for $($folder.Name)"
                    
                    # Send notification for large space recovery
                    if ($folderSize -gt 1GB) {
                        $recoveredSpaceGB = [Math]::Round($folderSize / 1GB, 2)
                        Send-SpaceRecoveryNotification -FolderPath $folder.FullName -SpaceGB $recoveredSpaceGB -TapeID $script:TapeUniqueID
                    }
                } else {
                    Log-Message "WARNING: Source cleanup failed for $($folder.Name): $deleteMessage"
                    Send-CleanupFailureAlert -FolderPath $folder.FullName -ErrorMessage $deleteMessage
                }
                
                # FUTURE: Dual tape copy
                # if ($EnableDualTape) {
                #     Log-Message "Copying to secondary tape..."
                #     $secondarySuccess = Copy-ToSecondaryTape -SourcePath $folder.FullName -FolderName $folder.Name
                #     if (-not $secondarySuccess) {
                #         Log-Message "WARNING: Secondary tape copy failed, but primary copy succeeded"
                #     }
                # }
            } else {
                $err = "Robocopy failed for $($folder.Name) with exit code $LASTEXITCODE"
                Log-Message "ERROR: $err"
                Log-Message "ROBOCOPY FAILED: $($folder.FullName) - $err"
                Send-Email -Subject "Tape Archive Error: Robocopy Failed" -Body $err -IsError $true
            }
        } catch {
            $err = "Robocopy exception: $($_.Exception.Message)"
            Log-Message "ERROR: $err"
            Log-Message "ROBOCOPY EXCEPTION: $($folder.FullName) - $err"
            Send-Email -Subject "Tape Archive Error: Robocopy Exception" -Body $err -IsError $true
        }

        Log-Message "--- Finished folder: $($folder.FullName) ---"
    }

    Log-Message "=== Finished server: $Server ==="
}

# ============================
# MAIN SCRIPT EXECUTION
# ============================

# Initialize log cleanup first
Initialize-LogCleanup

Log-Message "=== Tape Archiving Job Started ==="
Log-Message "Start time: $ScriptStartTime"
Log-Message "Processing servers: $($SourceServers -join ', ')"

try {
    # Test email credentials first
    Log-Message "Testing email credential setup..."
    if (-not (Test-EmailCredentialSetup)) {
        throw "Email credential setup test failed. Please check Windows Credential Manager configuration."
    }

    # Basic validation before proceeding
    if (-not (Test-Robocopy)) { 
        throw "Prerequisite Robocopy missing." 
    }

    Log-Message "Initializing DB..."
    if (-not (Test-DatabaseConnection)) { 
        throw "DB connection test failed." 
    }
    if (-not (Initialize-SQLiteDatabase)) { 
        throw "DB initialization failed." 
    }

    # Backup database before starting
    Log-Message "Backing up database..."
    Backup-Database

    # Enhanced tape drive validation with robust retry mechanism
    Log-Message "Validating tape drive: $TapeDrive"
    if (-not (Test-TapeDriveAvailable)) {
        $err = "Tape drive $TapeDrive is not accessible. Please ensure tape is inserted and LTFS formatted."
        Log-Message "CRITICAL: $err"
        throw $err
    }
    
    # Detect current tape with robust error handling
    $tapeResult = Get-TapeUniqueIDWithDetection -DriveLetter $TapeDrive
    $script:TapeUniqueID = $tapeResult[0]
    $script:TapeLabel = $tapeResult[1]
    
    Log-Message "Current tape: $script:TapeLabel [$script:TapeUniqueID]"
    
    # FUTURE: Initialize dual tape system
    # if ($EnableDualTape) {
    #     Initialize-DualTapeSystem
    # }
    
    # Check initial tape space
    $initialFreeSpace = Get-TapeFreeSpace
    if ($initialFreeSpace -le $TapeFullThreshold) {
        Log-Message "WARNING: Initial tape space ($([Math]::Round($initialFreeSpace/1GB,2)) GB) is below threshold ($([Math]::Round($TapeFullThreshold/1GB,2)) GB)"
        if ($initialFreeSpace -le 0) {
            Log-Message "CRITICAL: Tape appears to be completely full, initiating immediate tape swap"
            Invoke-TapeSwap -currentTapeLabel $script:TapeLabel -currentTapeUniqueID $script:TapeUniqueID
        }
    } else {
        Log-Message "Initial tape space OK: $([Math]::Round($initialFreeSpace/1GB,2)) GB free"
    }

    # Send startup email
    Log-Message "Sending startup email notification..."
    Send-StartupEmail

    # Iterate servers with individual error handling
    foreach ($server in $SourceServers) {
        try {
            Process-Server -Server $server
        } catch {
            $err = "Failed to process server $server : $($_.Exception.Message)"
            Log-Message "ERROR: $err"
            Send-Email -Subject "Tape Archive Error: Server Processing Failed" -Body $err -IsError $true
            # Continue with next server instead of stopping entirely
            continue
        }
    }

    $elapsed = (Get-Date) - $ScriptStartTime
    Log-Message "=== Tape Archiving Job Finished ==="
    Log-Message "Total time: $($elapsed.ToString('hh\:mm\:ss'))"
    Log-Message "DB file: $DatabasePath"

    # Backup database after completion
    Log-Message "Creating final database backup..."
    Backup-Database

    # Send completion email with detailed report
    Log-Message "Sending completion email with detailed report..."
    Send-CompletionEmail -Duration $elapsed

    # Log summary
    Log-Message "SUMMARY: Processed $($script:ProcessedServers.Count)/$($SourceServers.Count) servers successfully"
    if ($script:FailedServers.Count -gt 0) {
        Log-Message "FAILED SERVERS: $($script:FailedServers.Count) servers had issues"
        $script:FailedServers | ForEach-Object { Log-Message "  - $_" }
    }

} catch {
    $err = "Fatal error: $($_.Exception.Message)"
    Log-Message "CRITICAL ERROR: $err"
    
    $errorBody = @"
CRITICAL TAPE ARCHIVE FAILURE

Error: $($_.Exception.Message)
Script: $($MyInvocation.ScriptName)
Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Server: $env:COMPUTERNAME
Tape Drive Status: $(if ($script:TapeDriveAvailable) { "Available" } else { "Unavailable" })
Current Tape: $(if ($script:TapeLabel) { "$script:TapeLabel [$script:TapeUniqueID]" } else { "Unknown" })

Stack Trace:
$($_.ScriptStackTrace)

Please check the tape drive connectivity and script configuration immediately.

This is an automated alert from the Tape Archiving System.
"@
    
    Send-Email -Subject "CRITICAL: Tape Archive System Failure" -Body $errorBody -IsError $true
    exit 1
}