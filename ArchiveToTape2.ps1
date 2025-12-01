<# 
Enhanced Folder-Level Tape Archiving Script with SQLite Database Logging
HPE LTO-9 + Windows Server 2025
Features: hash-based duplicate detection, auto-generated TapeUniqueID, email alerts, long-job alerts,
multi-server support, log rotation, SQLite logging, vol-based label detection, robocopy-based folder copy,
tape-swap handling with automatic unique ID, network retry logic, and partial unique index for success rows.
#>

# ============================
# CONFIGURATION - EDIT THESE
# ============================
$SourceServers      = @("\\Test-SRV1\", "\\Test-SRV2")   # servers to scan
$SourceBasePath     = "InstallationFiles\Testing"                        # path on each server (relative)
$TapeDrive          = "F:"                                               # LTFS mount letter (include colon)
$LogFile            = "C:\TapeAutomation\Logs\ArchiveLog.txt"
$MaxLogSize         = 100MB                                              # rotate when >= this (bytes)
$TapeFullThreshold  = 1000GB                                             # reserve buffer (bytes)
$DaysThreshold      = 1                                                 # archive only folders older than X days
$MaxJobDurationHours= 20                                                 # long-job alert threshold

# Network retry tuning
$NetworkRetries     = 3
$NetworkRetryDelay  = 10   # seconds

# SQLite DB
$DatabasePath       = "C:\TapeAutomation\TapeArchive.db"
$DatabaseTable      = "TapeArchiveLog"

# Email (set EmailPass or use credential store)
$EmailFrom          = "testfrom@testing.com.au"
$EmailTo            = "testto@testing.com.au"
$SMTPServer         = "smtp.gmail.com"
$SMTPPort           = 587
$UseSSL             = $true
$EmailUser          = "testfrom@testing.com.au"
#$EmailPass         = "YOUR_APP_PASSWORD"   # prefer secure storage, or comment out to avoid plaintext

# ============================
# GLOBALS
# ============================
$ScriptStartTime = Get-Date
$script:EmailSentForCurrentTape = $false
$script:JobTimeoutAlertSent = $false
$script:TapeLabel = $null
$script:TapeUniqueID = $null

# ============================
# LOGGING + ROTATION
# ============================
Function Log-Message {
    param([string]$msg)
    try {
        $logDir = Split-Path $LogFile -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

        if (Test-Path $LogFile) {
            $logSize = (Get-Item $LogFile).Length
            if ($logSize -ge $MaxLogSize) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $rotatedLog = $LogFile -replace '\.txt$', "_$timestamp.txt"
                Move-Item -Path $LogFile -Destination $rotatedLog -Force
                Add-Content -Path $rotatedLog -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - [SYSTEM] Log file rotated from $LogFile"
            }
        }
        $timestampedMsg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
        Add-Content -Path $LogFile -Value $timestampedMsg
        Write-Host $timestampedMsg -ForegroundColor Cyan
    } catch {
        Write-Host "Log-Message failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================
# EMAIL SENDER
# ============================
Function Send-Email {
    param(
        [string]$Subject,
        [string]$Body,
        [bool]$IsError = $false
    )
    try {
        if (-not $EmailPass) {
            # Try to use a stored credential (optional)
            try {
                $cred = Get-StoredCredential -Target $SMTPServer -ErrorAction SilentlyContinue
                if ($cred) {
                    $securePass = $cred.Password | ConvertTo-SecureString -AsPlainText -Force
                    $credential = New-Object System.Management.Automation.PSCredential($EmailUser, $securePass)
                } else {
                    throw "No email password or stored credential found."
                }
            } catch {
                Log-Message "Email not sent: no credentials available. Subject: $Subject"
                return $false
            }
        } else {
            $securePass = ConvertTo-SecureString $EmailPass -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($EmailUser, $securePass)
        }

        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $Subject -Body $Body `
            -SmtpServer $SMTPServer -Port $SMTPPort -UseSsl:$UseSSL -Credential $credential -ErrorAction Stop
        Log-Message "Email sent: $Subject"
        return $true
    } catch {
        $errorMsg = "Failed to send email. Error: $($_.Exception.Message)"
        Log-Message "ERROR: $errorMsg"
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
        Write-Warning "Attempt $i/$Retries — path $Path not available. Retrying in $DelaySeconds seconds..."
        Start-Sleep -Seconds $DelaySeconds
    }
    return $false
}

# ============================
# SQLITE INIT + SCHEMA MGMT
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
    ServerName TEXT NOT NULL
);
CREATE INDEX IX_SourcePath ON $DatabaseTable (SourcePath);
CREATE INDEX IX_TapeLabel ON $DatabaseTable (TapeLabel);
CREATE INDEX IX_TapeUniqueID ON $DatabaseTable (TapeUniqueID);
CREATE INDEX IX_ArchiveDate ON $DatabaseTable (ArchiveDate);
CREATE INDEX IX_Status ON $DatabaseTable (Status);
CREATE INDEX IX_FolderHash ON $DatabaseTable (FolderHash);
CREATE INDEX IX_ServerName ON $DatabaseTable (ServerName);
-- Unique only for successful archives: prevents duplicate successful entries
CREATE UNIQUE INDEX IF NOT EXISTS IX_SourceHashSuccess ON $DatabaseTable (SourcePath, FolderHash) WHERE Status='SUCCESS';
"@
            Invoke-SqliteQuery -Query $query -DataSource $DatabasePath
            Log-Message "SUCCESS: DB created at $DatabasePath"
        } else {
            Log-Message "DB exists; checking schema..."
            $columns = Invoke-SqliteQuery -Query "PRAGMA table_info($DatabaseTable)" -DataSource $DatabasePath
            $hasTapeUnique = $columns | Where-Object { $_.name -eq "TapeUniqueID" }
            $hasFolderHash = $columns | Where-Object { $_.name -eq "FolderHash" }
            if (-not $hasTapeUnique) {
                Log-Message "Adding TapeUniqueID column..."
                Invoke-SqliteQuery -Query "ALTER TABLE $DatabaseTable ADD COLUMN TapeUniqueID TEXT" -DataSource $DatabasePath
            }
            if (-not $hasFolderHash) {
                Log-Message "Adding FolderHash column..."
                Invoke-SqliteQuery -Query "ALTER TABLE $DatabaseTable ADD COLUMN FolderHash TEXT NOT NULL DEFAULT 'N/A'" -DataSource $DatabasePath
                Invoke-SqliteQuery -Query "UPDATE $DatabaseTable SET FolderHash='LEGACY_RECORD' WHERE FolderHash='N/A'" -DataSource $DatabasePath
            }
            # create indexes if missing
            $idxs = @(
                "CREATE INDEX IF NOT EXISTS IX_FolderHash ON $DatabaseTable (FolderHash)",
                "CREATE INDEX IF NOT EXISTS IX_TapeUniqueID ON $DatabaseTable (TapeUniqueID)",
                "CREATE INDEX IF NOT EXISTS IX_ServerName ON $DatabaseTable (ServerName)"
            )
            foreach ($q in $idxs) { try { Invoke-SqliteQuery -Query $q -DataSource $DatabasePath } catch { Log-Message "INDEX WARN: $($_.Exception.Message)" } }

            # ensure partial unique exists
            try { Invoke-SqliteQuery -Query "CREATE UNIQUE INDEX IF NOT EXISTS IX_SourceHashSuccess ON $DatabaseTable (SourcePath, FolderHash) WHERE Status='SUCCESS'" -DataSource $DatabasePath } catch {}
            Log-Message "SUCCESS: DB schema ensured/updated."
        }
        return $true
    } catch {
        Log-Message "ERROR: Failed to initialize DB: $($_.Exception.Message)"
        Send-Email -Subject "Tape Archive Error: DB Init Failed" -Body "Error: $($_.Exception.Message)" -IsError $true
        return $false
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
# READ TAPE LABEL (vol command)
# ============================
Function Get-TapeLabel {
    param([string]$DriveLetter = $TapeDrive)
    $drive = $DriveLetter.TrimEnd(':')
    Log-Message "Reading label for drive $drive"
    try {
        $volOutput = & cmd.exe /c "vol ${drive}:"
        $labelLine = $volOutput | Where-Object { $_ -like " Volume in drive*" }
        if ($labelLine -match "Volume in drive ${drive} is (.+)") {
            $label = $matches[1].Trim()
            if (-not [string]::IsNullOrEmpty($label)) { Log-Message "Read tape label: $label"; return $label }
        }
        if ($volOutput -like "*has no label*") {
            Log-Message "Drive $drive has no label set."
            $generated = "Tape_$(Get-Date -Format 'yyyyMMdd_HHmm')"
            Log-Message "Generated label: $generated"
            return $generated
        }
    } catch {
        Log-Message "WARNING: Failed to read volume label: $($_.Exception.Message)"
    }
    $generated = "Tape_$(Get-Date -Format 'yyyyMMdd_HHmm')"
    Log-Message "WARNING: Using generated label: $generated"
    return $generated
}

# ============================
# AUTO-GENERATE TAPE UNIQUE ID
# ============================
Function Get-AutoTapeUniqueID {
    param([string]$TapeLabel)
    $timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
    $random = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    return "${TapeLabel}_${timestamp}_${random}"
}

# ============================
# TAPE FULL EMAIL (includes unique id)
# ============================
Function Send-TapeFullEmail {
    param($tapeLabel, $tapeUniqueID, $freeSpace)
    $subject = "Tape Storage Almost Full: $tapeLabel [$tapeUniqueID]"
    $body = @"
Tape Storage Almost Full

Tape Label: $tapeLabel
Tape Unique ID: $tapeUniqueID
Remaining Free Space: $([Math]::Round($freeSpace/1GB,2)) GB

Please prepare and insert the next tape to continue archiving.

This is an automated message from the Tape Archiving System.
"@
    Send-Email -Subject $subject -Body $body
}

# ============================
# ROBocopy check
# ============================
Function Test-Robocopy {
    try { $rc = Get-Command "robocopy.exe" -ErrorAction Stop; Log-Message "Robocopy: $($rc.Source)"; return $true }
    catch { Log-Message "ERROR: Robocopy not present"; Send-Email -Subject "Tape Archive Error: Robocopy Missing" -Body "Robocopy required"; return $false }
}

# ============================
# AGE CHECK
# ============================
Function Test-FolderOlderThanDays { param([System.IO.DirectoryInfo]$Folder, [int]$Days)
    $cutoff = (Get-Date).AddDays(-$Days)
    $isOlder = $Folder.LastWriteTime -lt $cutoff
    Log-Message "Folder $($Folder.FullName) last write: $($Folder.LastWriteTime) cutoff: $cutoff older:$isOlder"
    return $isOlder
}

# ============================
# DB CONNECTION TEST
# ============================
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

# ============================
# JOB DURATION WATCHDOG
# ============================
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
# PROCESS A SINGLE SERVER
# ============================
Function Process-Server {
    param([string]$Server)
    $SourceDir = Join-Path $Server $SourceBasePath
    Log-Message "=== Processing server: $Server ==="
    Log-Message "Source directory: $SourceDir"

    if (-not (Test-NetworkPath -Path $SourceDir)) {
        $err = "Source $SourceDir unreachable after $NetworkRetries attempts."
        Log-Message "WARNING: $err"
        # Only log to file, not database
        Log-Message "VALIDATION FAILED: $SourceDir - $err"
        return
    }

    try {
        $folders = Get-ChildItem -Path $SourceDir -Directory -ErrorAction Stop
        Log-Message "Found $($folders.Count) folders on $Server"
    } catch {
        $err = "Could not list directories: $($_.Exception.Message)"
        Log-Message "ERROR: $err"
        # Only log to file, not database
        Log-Message "FOLDER LISTING FAILED: $SourceDir - $err"
        Send-Email -Subject "Tape Archive Error: Folder Listing Failed on $Server" -Body $err -IsError $true
        return
    }

    foreach ($folder in $folders) {
        # periodic job duration checks
        if ($folders.Count -gt 2 -and ($folder.Name -in @($folders[0].Name, $folders[[math]::Floor($folders.Count/2)].Name, $folders[-1].Name))) { Check-JobDuration }
        Log-Message "--- Evaluating folder: $($folder.FullName) ---"

        if (-not (Test-FolderOlderThanDays -Folder $folder -Days $DaysThreshold)) {
            Log-Message "Skipping (not old enough): $($folder.FullName)"
            # Only log to file, not database
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
            # Only log to file, not database
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
            # Only log to file, not database
            Log-Message "SIZE CALCULATION FAILED: $($folder.FullName) - $err"
            continue
        }

        # check tape free space
        try {
            $tapeDriveInfo = Get-PSDrive -Name $TapeDrive.TrimEnd(':') -ErrorAction Stop
            $freeSpace = $tapeDriveInfo.Free
            Log-Message "Tape free space: $([Math]::Round($freeSpace/1GB,2)) GB"
        } catch {
            $err = "Tape free space check failed: $($_.Exception.Message)"
            Log-Message "ERROR: $err"
            # Only log to file, not database
            Log-Message "TAPE SPACE CHECK FAILED: $($folder.FullName) - $err"
            continue
        }

        if (($folderSize + $TapeFullThreshold) -gt $freeSpace) {
            Log-Message "WARNING: Tape $($script:TapeLabel) [$($script:TapeUniqueID)] has insufficient space for $($folder.Name)."
            if (-not $script:EmailSentForCurrentTape) {
                Send-TapeFullEmail -tapeLabel $script:TapeLabel -tapeUniqueID $script:TapeUniqueID -freeSpace $freeSpace
                $script:EmailSentForCurrentTape = $true
                # Only log to file, not database
                Log-Message "TAPE FULL ALERT SENT: $($script:TapeLabel) [$($script:TapeUniqueID)]"
            }

            Write-Host "Please insert a new tape and ensure it is formatted and mounted as $TapeDrive. Press Enter to continue, or Ctrl+C to abort..." -ForegroundColor Yellow
            Read-Host | Out-Null

            try {
                if (-not (Test-Path -Path ("${TapeDrive}\") -PathType Container)) { throw "New tape path not found after swap." }
                $newLabel = Get-TapeLabel
                if ($newLabel -eq $script:TapeLabel) { Log-Message "WARNING: Loaded tape label equals previous label ($newLabel)." }
                $newUnique = Get-AutoTapeUniqueID -TapeLabel $newLabel

                $script:TapeLabel = $newLabel
                $script:TapeUniqueID = $newUnique
                $tapeDriveInfo = Get-PSDrive -Name $TapeDrive.TrimEnd(':')
                $freeSpace = $tapeDriveInfo.Free
                $script:EmailSentForCurrentTape = $false

                Log-Message "New tape loaded: $script:TapeLabel [$script:TapeUniqueID] Free: $([Math]::Round($freeSpace/1GB,2)) GB"
                # Only log to file, not database
                Log-Message "NEW TAPE LOADED: $script:TapeLabel [$script:TapeUniqueID]"
            } catch {
                $err = "Failed to access new tape: $($_.Exception.Message)"
                Log-Message "ERROR: $err"
                # Only log to file, not database
                Log-Message "TAPE SWAP FAILED: $($folder.FullName) - $err"
                Send-Email -Subject "Tape Archive Error: Tape Swap Failed on $Server" -Body $err -IsError $true
                throw
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
                # Only SUCCESS records are written to database
                Write-DatabaseLog -SourcePath $folder.FullName -TapeLabel $script:TapeLabel -TapeUniqueID $script:TapeUniqueID -SizeBytes $folderSize -FolderHash $folderHash -Status "SUCCESS" -FileCount $fileCount -ServerName $Server
            } else {
                $err = "Robocopy failed for $($folder.Name) with exit code $LASTEXITCODE"
                Log-Message "ERROR: $err"
                # Only log to file, not database
                Log-Message "ROBOCOPY FAILED: $($folder.FullName) - $err"
                Send-Email -Subject "Tape Archive Error: Robocopy Failed" -Body $err -IsError $true
            }
        } catch {
            $err = "Robocopy exception: $($_.Exception.Message)"
            Log-Message "ERROR: $err"
            # Only log to file, not database
            Log-Message "ROBOCOPY EXCEPTION: $($folder.FullName) - $err"
            Send-Email -Subject "Tape Archive Error: Robocopy Exception" -Body $err -IsError $true
        }

        Log-Message "--- Finished folder: $($folder.FullName) ---"
    }

    Log-Message "=== Finished server: $Server ==="
}

# ============================
# MAIN SCRIPT
# ============================
Log-Message "=== Tape Archiving Job Started ==="
Log-Message "Start time: $ScriptStartTime"
Log-Message "Processing servers: $($SourceServers -join ', ')"

try {
    if (-not (Test-Robocopy)) { throw "Prerequisite Robocopy missing." }

    Log-Message "Initializing DB..."
    if (-not (Test-DatabaseConnection)) { throw "DB connection test failed." }
    if (-not (Initialize-SQLiteDatabase)) { throw "DB initialization failed." }

    Log-Message "Validating tape drive: $TapeDrive"
    try {
        $tapeDriveRoot = "${TapeDrive}\"
        if (-not (Test-Path -Path $tapeDriveRoot -PathType Container)) { throw "Tape drive root not found. Is the tape inserted and LTFS formatted?" }
        $script:TapeLabel = Get-TapeLabel
        $script:TapeUniqueID = Get-AutoTapeUniqueID -TapeLabel $script:TapeLabel
        Log-Message "Current tape: $script:TapeLabel [$script:TapeUniqueID]"
        # Only log to file, not database
        Log-Message "TAPE VALIDATED: $script:TapeLabel [$script:TapeUniqueID]"
    } catch {
        $err = "Tape validation failed: $($_.Exception.Message)"
        Log-Message "ERROR: $err"
        # Only log to file, not database
        Log-Message "TAPE VALIDATION FAILED: $err"
        Send-Email -Subject "Tape Archive Error: Tape Validation Failed" -Body $err -IsError $true
        throw $err
    }

    # iterate servers
    foreach ($server in $SourceServers) { Process-Server -Server $server }

    $elapsed = (Get-Date) - $ScriptStartTime
    Log-Message "=== Tape Archiving Job Finished ==="
    Log-Message "Total time: $($elapsed.ToString('hh\:mm\:ss'))"
    Log-Message "DB file: $DatabasePath"

    if ($elapsed.TotalHours -ge 1) {
        $subject = "Tape Archive Job Completed Successfully"
        $body = @"
Tape Archive Job Completion Notification

Job completed successfully in $($elapsed.ToString('hh\:mm\:ss')).

Start Time: $($ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
End Time: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Total Duration: $($elapsed.ToString('hh\:mm\:ss'))

Servers processed: $($SourceServers -join ', ')
Tape used: $($script:TapeLabel) [$($script:TapeUniqueID)]

This is an automated message from the Tape Archiving System.
"@
        Send-Email -Subject $subject -Body $body
    }

} catch {
    $err = "Fatal error: $($_.Exception.Message)"
    Log-Message "CRITICAL ERROR: $err"
    Send-Email -Subject "Tape Archive Error: Fatal Script Error" -Body $err -IsError $true
    exit 1
}