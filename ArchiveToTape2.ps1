# ----------------------------
# Folder-Level Tape Archiving Script
# HPE LTO-9 + Windows Server 2025
# Features:
# - Bulletproof tape label detection using the 'vol' command
# - Folder-level atomic copying using Robocopy for resilience
# - Comprehensive logging to file and console
# - Email alert when tape is almost full
# - Pre-flight checks for source, destination, and dependencies
# - Only archives folders older than 60 days (based on last write time)
# ----------------------------

# CONFIGURATION
$SourceDir = "\\Test-SRV\sushan"          # Network source to archive
$TapeDrive = "F:"                                  # LTO-9 tape drive (LTFS-mounted)
$IndexFile = "C:\TapeAutomation\TapeIndex.csv"
$LogFile = "C:\TapeAutomation\Logs\ArchiveLog.txt"
$TapeFullThreshold = 16500GB                         # Reserve buffer to avoid overfill
$DaysThreshold = 60                                # Only archive folders older than this many days

# EMAIL CONFIGURATION
$EmailFrom   = "sxenix@gmail.com"
$EmailTo     = "x_enix@msn.com"
$SMTPServer  = "smtp.gmail.com"
$SMTPPort    = 587
$UseSSL      = $true
$EmailUser   = "sxenix@gmail.com"
$EmailPass   = "YOUR_APP_PASSWORD"                  # Replace with Google App Password

# LOG FUNCTION
Function Log-Message {
    param([string]$msg)
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $timestampedMsg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
    Add-Content -Path $LogFile -Value $timestampedMsg
    Write-Host $timestampedMsg -ForegroundColor Cyan
}

# FUNCTION TO GET CURRENT TAPE LABEL (BULLETPROOF METHOD USING 'VOL' COMMAND)
Function Get-TapeLabel {
    param ([string]$DriveLetter = $TapeDrive)
    
    $driveLetter = $DriveLetter.TrimEnd(':')
    Log-Message "Reading label for drive $driveLetter using vol command"

    try {
        $volOutput = & cmd.exe /c "vol ${driveLetter}:"
        $labelLine = $volOutput | Where-Object { $_ -like " Volume in drive*" }

        if ($labelLine -match "Volume in drive ${driveLetter} is (.+)") {
            $label = $matches[1].Trim()
            if (-not [string]::IsNullOrEmpty($label)) {
                Log-Message "SUCCESS: Read tape label: '$label'"
                return $label
            }
        }

        if ($volOutput -like "*has no label*") {
            Log-Message "Drive $driveLetter has no label set."
            $generatedLabel = "Tape_$(Get-Date -Format 'yyyyMMdd_HHmm')"
            Log-Message "Generated label: '$generatedLabel'"
            return $generatedLabel
        }
        
    } catch {
        Log-Message "WARNING: Failed to read volume label for $driveLetter. Error: $($_.Exception.Message)"
    }

    $generatedLabel = "Tape_$(Get-Date -Format 'yyyyMMdd_HHmm')"
    Log-Message "WARNING: Could not determine tape label. Generated label: '$generatedLabel'"
    return $generatedLabel
}

# FUNCTION TO SEND EMAIL ALERT
Function Send-TapeFullEmail {
    param($tapeLabel, $freeSpace)
    $subject = "Tape Storage Almost Full: $tapeLabel"
    $body = @"
Tape Storage Almost Full 

Tape Label: $tapeLabel
Remaining Free Space: $([Math]::Round($freeSpace/1GB,2)) GB

Please prepare and insert the next tape to continue archiving.

This is an automated message from the Tape Archiving System.
"@
   
    try {
        $securePass = ConvertTo-SecureString $EmailPass -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($EmailUser, $securePass)
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject $subject -Body $body `
            -SmtpServer $SMTPServer -Port $SMTPPort -UseSsl:$UseSSL -Credential $credential -ErrorAction Stop
        Log-Message "Email alert sent for tape $tapeLabel."
    } catch {
        Log-Message "WARNING: Failed to send email. Error: $($_.Exception.Message)"
    }
}

# FUNCTION TO CHECK FOR ROBOCOPY
Function Test-Robocopy {
    try {
        $robocopyPath = Get-Command "robocopy.exe" -ErrorAction Stop
        Log-Message "Robocopy found at: $($robocopyPath.Source)"
        return $true
    } catch {
        Log-Message "ERROR: Robocopy is not available. It is required for this script. Please ensure it is installed (part of Windows Server)."
        return $false
    }
}

# FUNCTION TO CHECK IF FOLDER IS OLDER THAN SPECIFIED DAYS
Function Test-FolderOlderThanDays {
    param([System.IO.DirectoryInfo]$Folder, [int]$Days)
    
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $isOlder = $Folder.LastWriteTime -lt $cutoffDate
    
    Log-Message "Folder '$($Folder.Name)' last write time: $($Folder.LastWriteTime). Cutoff: $cutoffDate. Is older than $Days days: $isOlder"
    return $isOlder
}

# --- MAIN SCRIPT EXECUTION STARTS HERE ---
Log-Message "=== Tape Archiving Job Started ==="
Log-Message "Only archiving folders older than $DaysThreshold days (last write time before $(Get-Date).AddDays(-$DaysThreshold))"

$EmailSentForCurrentTape = $false  # Prevent duplicate alerts for same tape

# 0. PREREQUISITE CHECK: Is Robocopy available?
if (-not (Test-Robocopy)) {
    throw "Prerequisite check failed. Exiting."
}

# 1. VALIDATE SOURCE DIRECTORY EXISTS
Log-Message "Validating source directory: $SourceDir"
if (-not (Test-Path -Path $SourceDir -PathType Container)) {
    $errorMsg = "FATAL ERROR: Source path $SourceDir does not exist or is inaccessible. Check the path and network permissions."
    Log-Message $errorMsg
    throw $errorMsg
}
Log-Message "Source directory validated successfully."

# 2. VALIDATE TAPE DRIVE IS READY AND GET LABEL
Log-Message "Validating tape drive: $TapeDrive"
try {
    $tapeDriveRoot = "${TapeDrive}\"
    if (-not (Test-Path -Path $tapeDriveRoot -PathType Container)) {
        throw "Tape drive root path not found. Is the tape inserted and formatted with LTFS?"
    }
    $tapeLabel = Get-TapeLabel
    Log-Message "Current tape identified: $tapeLabel"
} catch {
    $errorMsg = "FATAL: Could not validate tape drive $TapeDrive. Error: $($_.Exception.Message)"
    Log-Message $errorMsg
    throw $errorMsg
}

# 3. GET LIST OF FOLDERS TO ARCHIVE
try {
    $folders = Get-ChildItem -Path $SourceDir -Directory -ErrorAction Stop
    Log-Message "Found $($folders.Count) folders to evaluate."
} catch {
    $errorMsg = "ERROR: Could not list directories in $SourceDir. Error: $($_.Exception.Message)"
    Log-Message $errorMsg
    throw $errorMsg
}

# 4. INITIALIZE INDEX FILE
if (-not (Test-Path $IndexFile)) {
    $indexDir = Split-Path $IndexFile -Parent
    if (-not (Test-Path $indexDir)) { New-Item -Path $indexDir -ItemType Directory -Force | Out-Null }
    "SourcePath,TapeLabel,SizeBytes,ArchiveDate" | Out-File -FilePath $IndexFile -Encoding UTF8
    Log-Message "Created new index file: $IndexFile"
}

# 5. PROCESS EACH FOLDER
foreach ($folder in $folders) {
    Log-Message "--- Evaluating folder: $($folder.Name) ---"

    # CHECK IF FOLDER IS OLDER THAN 60 DAYS
    $isOlder = Test-FolderOlderThanDays -Folder $folder -Days $DaysThreshold
    
    if (-not $isOlder) {
        Log-Message "Folder '$($folder.Name)' is NOT older than $DaysThreshold days. Skipping."
        continue
    }
    
    Log-Message "Folder '$($folder.Name)' is older than $DaysThreshold days. Proceeding with archive."

    # CALCULATE FOLDER SIZE (ENTIRE CONTENTS)
    try {
        $folderSize = (Get-ChildItem $folder.FullName -Recurse -File | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum
        if (-not $folderSize) { $folderSize = 0 }
        Log-Message "Calculated folder size: $([Math]::Round($folderSize/1GB, 2)) GB"
    } catch {
        Log-Message "ERROR calculating size for $($folder.Name): $($_.Exception.Message). Skipping."
        continue
    }

    # CHECK TAPE FREE SPACE (REFRESH BEFORE EACH COPY)
    try {
        $tapeDriveInfo = Get-PSDrive -Name $TapeDrive.TrimEnd(':') -ErrorAction Stop
        $freeSpace = $tapeDriveInfo.Free
        Log-Message "Tape free space: $([Math]::Round($freeSpace/1GB,2)) GB"
    } catch {
        Log-Message "ERROR checking tape free space. Skipping folder."
        continue
    }

    # CHECK IF TAPE HAS ENOUGH SPACE
    if (($folderSize + $TapeFullThreshold) -gt $freeSpace) {
        Log-Message "WARNING: Tape '$tapeLabel' has insufficient space for folder '$($folder.Name)'."

        if (-not $EmailSentForCurrentTape) {
            Send-TapeFullEmail -tapeLabel $tapeLabel -freeSpace $freeSpace
            $EmailSentForCurrentTape = $true
        }

        Write-Host "Please insert a new tape and ensure it is formatted and mounted as $TapeDrive. Press Enter to continue, or Ctrl+C to abort..." -ForegroundColor Yellow
        Read-Host

        # Refresh tape info after swap
        try {
            if (-not (Test-Path -Path $tapeDriveRoot -PathType Container)) {
                throw "New tape drive path not found after swap."
            }
            $tapeLabel = Get-TapeLabel
            $tapeDriveInfo = Get-PSDrive -Name $TapeDrive.TrimEnd(':')
            $freeSpace = $tapeDriveInfo.Free
            $EmailSentForCurrentTape = $false  # Reset flag for new tape
            Log-Message "New tape loaded: $tapeLabel. Free space: $([Math]::Round($freeSpace/1GB,2)) GB"
        } catch {
            Log-Message "FATAL: Failed to access new tape. Aborting."
            throw $_
        }
    }

    # COPY ENTIRE FOLDER TO TAPE USING ROBOCOPY (NO AGE FILTER)
    $destinationPath = Join-Path -Path $TapeDrive -ChildPath $folder.Name
    Log-Message "Starting Robocopy to: $destinationPath (copying entire folder contents)"

    try {
        # Robocopy WITHOUT age filter - copies all files in the folder
        & robocopy.exe "$($folder.FullName)" "$destinationPath" /MIR /Z /J /R:3 /W:5 /NP /LOG+:$LogFile

        if ($LASTEXITCODE -lt 8) {
            Log-Message "SUCCESS: Robocopy finished for $($folder.Name). Exit code: $LASTEXITCODE"
            $entry = "$($folder.FullName),$tapeLabel,$folderSize,$(Get-Date -Format yyyy-MM-dd)"
            Add-Content -Path $IndexFile -Value $entry
            Log-Message "Index updated for $($folder.Name)."
        } else {
            Log-Message "ERROR: Robocopy failed for $($folder.Name) with exit code $LASTEXITCODE (serious error)."
        }
    } catch {
        Log-Message "ERROR during Robocopy operation: $($_.Exception.Message)"
    }

    Log-Message "--- Finished processing folder: $($folder.Name) ---"
}

Log-Message "=== Tape Archiving Job Finished Successfully ==="