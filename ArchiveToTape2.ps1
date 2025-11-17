# ----------------------------
# Folder-Level Tape Archiving Script
# HPE LTO-9 + Windows Server 2025
# Features:
# - Robust tape label detection with multiple fallback methods
# - Folder-level atomic copying using Robocopy for resilience
# - Comprehensive logging to file and console
# - Email alert when tape is almost full
# - Pre-flight checks for source, destination, and dependencies
# ----------------------------

# CONFIGURATION
$SourceDir = "\\Test-srv\sushan"          # Network source to archive
$TapeDrive = "F:"                                  # LTO-9 tape drive (LTFS-mounted)
$IndexFile = "C:\TapeAutomation\TapeIndex.csv"
$LogFile = "C:\TapeAutomation\Logs\ArchiveLog.txt"
$TapeFullThreshold = 100GB                         # Reserve buffer to avoid overfill

# EMAIL CONFIGURATION
$EmailFrom   = "sxenix@gmail.com"
$EmailTo     = "x_enix@msn.com"
$SMTPServer  = "smtp.gmail.com"
$SMTPPort    = 587
$UseSSL      = $true
$EmailUser   = "sxenix@gmail.com"
$EmailPass   = "YOUR_APP_PASSWORD"                 # Replace with Google App Password

# LOG FUNCTION
Function Log-Message {
    param([string]$msg)
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $timestampedMsg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $msg"
    Add-Content -Path $LogFile -Value $timestampedMsg
    Write-Host $timestampedMsg -ForegroundColor Cyan
}

# FUNCTION TO GET CURRENT TAPE LABEL (MULTI-METHOD FALLBACK)
Function Get-TapeLabel {
    param ([string]$DriveLetter = $TapeDrive)
    
    $driveLetter = $DriveLetter.TrimEnd(':')
    Log-Message "DEBUG: Attempting to read label for drive $driveLetter"

    try {
        # Method 1: Use Get-Volume (most reliable for NTFS/LTFS)
        $vol = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
        if ($vol.FileSystemLabel) {
            $label = $vol.FileSystemLabel.Trim()
            Log-Message "SUCCESS: Read tape label via Get-Volume: '$label'"
            return $label
        } else {
            Log-Message "WARNING: Get-Volume found drive $driveLetter but the FileSystemLabel is empty."
        }
    } catch {
        Log-Message "WARNING: Get-Volume failed for drive $driveLetter. Error: $($_.Exception.Message)"
    }

    try {
        # Method 2: Use WMI as a fallback (Win32_Volume)
        $vol = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = '$($driveLetter):'" -ErrorAction Stop
        if ($vol -and $vol.Label) {
            $label = $vol.Label.Trim()
            Log-Message "SUCCESS: Read tape label via WMI: '$label'"
            return $label
        }
    } catch {
        Log-Message "WARNING: WMI method also failed for drive $driveLetter."
    }

    # Method 3: Final fallback - Check the root directory for a common label file
    $commonLabelFiles = @("barcode.txt", "volinfo.txt", "label.txt", "tape_id.txt")
    foreach ($file in $commonLabelFiles) {
        $labelFilePath = Join-Path -Path "${driveLetter}:\" -ChildPath $file
        if (Test-Path $labelFilePath) {
            $label = (Get-Content $labelFilePath -First 1 -ErrorAction SilentlyContinue).Trim()
            if ($label) {
                Log-Message "SUCCESS: Read tape label from file '$file': '$label'"
                return $label
            }
        }
    }

    # Ultimate fallback: Generate a unique label based on the date
    $generatedLabel = "Tape_$(Get-Date -Format 'yyyyMMdd_HHmm')"
    Log-Message "WARNING: Could not determine tape label. Generated label: '$generatedLabel'"
    return $generatedLabel
}

# FUNCTION TO SEND EMAIL ALERT
Function Send-TapeFullEmail {
    param($tapeLabel, $freeSpace)
    $subject = "Tape Storage Almost Full: $tapeLabel"
    $body = "Attention: Tape '$tapeLabel' is running low on space.`nRemaining space: $([Math]::Round($freeSpace/1GB,2)) GB`nPlease prepare the next tape."
   
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

# --- MAIN SCRIPT EXECUTION STARTS HERE ---
Log-Message "=== Tape Archiving Job Started ==="

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
    $tapeLabel = Get-TapeLabel # This function has its own error handling
    Log-Message "Current tape identified: $tapeLabel"
} catch {
    $errorMsg = "FATAL: Could not validate tape drive $TapeDrive. Error: $($_.Exception.Message)"
    Log-Message $errorMsg
    throw $errorMsg
}

# 3. GET LIST OF FOLDERS TO ARCHIVE
try {
    $folders = Get-ChildItem -Path $SourceDir -Directory -ErrorAction Stop
    Log-Message "Found $($folders.Count) folders to process."
} catch {
    $errorMsg = "ERROR: Could not list directories in $SourceDir. Error: $($_.Exception.Message)"
    Log-Message $errorMsg
    throw $errorMsg
}

# 4. INITIALIZE INDEX FILE (if it doesn't exist)
if (-not (Test-Path $IndexFile)) {
    $indexDir = Split-Path $IndexFile -Parent
    if (-not (Test-Path $indexDir)) { New-Item -Path $indexDir -ItemType Directory -Force | Out-Null }
    "SourcePath,TapeLabel,SizeBytes,ArchiveDate" | Out-File -FilePath $IndexFile -Encoding UTF8
    Log-Message "Created new index file: $IndexFile"
}

# 5. PROCESS EACH FOLDER
foreach ($folder in $folders) {
    Log-Message "--- Starting processing for folder: $($folder.Name) ---"

    # CALCULATE FOLDER SIZE
    try {
        $folderSize = (Get-ChildItem $folder.FullName -Recurse -File | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum
        if (-not $folderSize) { $folderSize = 0 } # Handle empty folders
        Log-Message "Calculated folder size: $([Math]::Round($folderSize/1GB, 2)) GB"
    } catch {
        Log-Message "ERROR calculating size for $($folder.Name): $($_.Exception.Message). Skipping."
        continue
    }

    # CHECK TAPE FREE SPACE (Refresh this before each folder)
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
        Send-TapeFullEmail -tapeLabel $tapeLabel -freeSpace $freeSpace

        Write-Host "Please insert a new tape and ensure it is formatted and mounted as $TapeDrive. Press Enter to continue, or Ctrl+C to abort..." -ForegroundColor Yellow
        Read-Host

        # Refresh tape info after swap
        try {
            # Re-check the drive is accessible
            if (-not (Test-Path -Path $tapeDriveRoot -PathType Container)) {
                throw "New tape drive path not found after swap."
            }
            $tapeLabel = Get-TapeLabel
            $tapeDriveInfo = Get-PSDrive -Name $TapeDrive.TrimEnd(':')
            $freeSpace = $tapeDriveInfo.Free
            Log-Message "New tape loaded: $tapeLabel. Free space: $([Math]::Round($freeSpace/1GB,2)) GB"
        } catch {
            Log-Message "FATAL: Failed to access new tape. Aborting."
            throw $_
        }
    }

    # COPY FOLDER TO TAPE USING ROBOCPY
    $destinationPath = Join-Path -Path $TapeDrive -ChildPath $folder.Name
    Log-Message "Starting Robocopy to: $destinationPath"

    try {
        & robocopy.exe "$($folder.FullName)" "$destinationPath" /MIR /Z /J /R:3 /W:5 /NP /LOG+:$LogFile
        # /MIR: Mirror mode (copies all data and purges deleted files on destination)
        # /Z: restartable mode
        # /J: unbuffered I/O (good for large files)
        # /R:3: retry 3 times
        # /W:5: wait 5 sec between retries
        # /NP: No Progress (keeps log readable)
        # /LOG+: Append to log file

        # Check Robocopy's exit code
        if ($LASTEXITCODE -lt 8) {
            # Exit codes 0-7 are success or partial success
            Log-Message "SUCCESS: Robocopy finished for $($folder.Name). Exit code: $LASTEXITCODE"

            # UPDATE INDEX
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