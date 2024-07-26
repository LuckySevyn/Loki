# Define the password (you can also input it securely using Read-Host)
$YourPassword = Read-Host "Password is" -AsSecureString

# Convert the SecureString password to a plain text string (needed for the encryption functions)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($YourPassword))

# Ensure the required module is available
if (-not (Get-Module -ListAvailable -Name 'Microsoft.PowerShell.Security')) {
    Install-Module -Name 'Microsoft.PowerShell.Security' -Scope CurrentUser -Force
}

function Get-EncryptedKey {
    param (
        [string]$Password
    )
    $salt = [System.Text.Encoding]::UTF8.GetBytes("YourSaltHere")  # Use a fixed salt or generate a new one for each encryption
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
    return $pbkdf2.GetBytes(32)  # AES-256 key length
}

function Encrypt-Folder {
    param (
        [string]$FolderPath,
        [string]$OutputFilePath,
        [string]$Password
    )

    $key = Get-EncryptedKey -Password $Password
    $aes = [System.Security.Cryptography.Aes]::Create()
    $iv = $aes.IV  # Generate a random IV

    $files = Get-ChildItem -Path $FolderPath -Recurse
    $compressedStream = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GzipStream($compressedStream, [System.IO.Compression.CompressionMode]::Compress)

    foreach ($file in $files) {
        if (-not $file.PSIsContainer) {
            $relativePath = $file.FullName.Substring($FolderPath.Length + 1)
            $relativePathBytes = [System.Text.Encoding]::UTF8.GetBytes($relativePath)
            $relativePathLengthBytes = [BitConverter]::GetBytes($relativePathBytes.Length)

            # Write length of the relative path, followed by the relative path, followed by the file contents
            $gzipStream.Write($relativePathLengthBytes, 0, $relativePathLengthBytes.Length)
            $gzipStream.Write($relativePathBytes, 0, $relativePathBytes.Length)

            $fileBytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $fileLengthBytes = [BitConverter]::GetBytes($fileBytes.Length)
            $gzipStream.Write($fileLengthBytes, 0, $fileLengthBytes.Length)
            $gzipStream.Write($fileBytes, 0, $fileBytes.Length)
        }
    }
    $gzipStream.Close()
    $compressedData = $compressedStream.ToArray()
    $compressedStream.Close()

    $aes.Key = $key
    $aes.IV = $iv
    $encryptor = $aes.CreateEncryptor()

    $outputStream = [System.IO.File]::Create($OutputFilePath)
    $outputStream.Write($iv, 0, $iv.Length)  # Write IV first
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outputStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cryptoStream.Write($compressedData, 0, $compressedData.Length)
    $cryptoStream.FlushFinalBlock()
    $cryptoStream.Close()
    $outputStream.Close()

    # Set file permissions
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -Path $OutputFilePath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
    $acl.AddAccessRule($rule)
    $acl.SetAccessRuleProtection($true, $false)  # Protect ACL and remove inheritance
    Set-Acl -Path $OutputFilePath -AclObject $acl
}

function Decrypt-Folder {
    param (
        [string]$InputFilePath,
        [string]$OutputFolderPath,
        [string]$Password
    )

    $key = Get-EncryptedKey -Password $Password

    # Check and restore file permissions for the current user
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -Path $InputFilePath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")
    $acl.AddAccessRule($rule)
    $acl.SetAccessRuleProtection($true, $false)  # Protect ACL and remove inheritance
    Set-Acl -Path $InputFilePath -AclObject $acl

    $inputStream = [System.IO.File]::OpenRead($InputFilePath)
    $iv = New-Object byte[] 16
    $inputStream.Read($iv, 0, $iv.Length)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $decryptor = $aes.CreateDecryptor()

    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($inputStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
    $gzipStream = New-Object System.IO.Compression.GzipStream($cryptoStream, [System.IO.Compression.CompressionMode]::Decompress)

    $outputFolder = [System.IO.Directory]::CreateDirectory($OutputFolderPath)

    try {
        while ($true) {
            # Read the length of the relative path
            $relativePathLengthBytes = New-Object byte[] 4
            if ($gzipStream.Read($relativePathLengthBytes, 0, 4) -ne 4) { break }
            $relativePathLength = [BitConverter]::ToInt32($relativePathLengthBytes, 0)

            # Read the relative path
            $relativePathBytes = New-Object byte[] $relativePathLength
            if ($gzipStream.Read($relativePathBytes, 0, $relativePathLength) -ne $relativePathLength) { break }
            $relativePath = [System.Text.Encoding]::UTF8.GetString($relativePathBytes)

            # Read the length of the file data
            $fileLengthBytes = New-Object byte[] 4
            if ($gzipStream.Read($fileLengthBytes, 0, 4) -ne 4) { break }
            $fileLength = [BitConverter]::ToInt32($fileLengthBytes, 0)

            # Read the file data
            $fileBytes = New-Object byte[] $fileLength
            $totalBytesRead = 0
            while ($totalBytesRead -lt $fileLength) {
                $bytesRead = $gzipStream.Read($fileBytes, $totalBytesRead, $fileLength - $totalBytesRead)
                if ($bytesRead -le 0) { break }
                $totalBytesRead += $bytesRead
            }
            if ($totalBytesRead -ne $fileLength) { break }

            $filePath = Join-Path -Path $OutputFolderPath -ChildPath $relativePath
            $directory = [System.IO.Path]::GetDirectoryName($filePath)

            if (-not (Test-Path -Path $directory)) {
                [System.IO.Directory]::CreateDirectory($directory)
            }
            [System.IO.File]::WriteAllBytes($filePath, $fileBytes)
        }
    }
    finally {
        $gzipStream.Close()
        $cryptoStream.Close()
        $inputStream.Close()
    }
}

# Usage - Uncomment the below function that you want to use (Only do one at a time!)

# Encrypt
# Encrypt-Folder -FolderPath "C:\PATH\TO\FOLDER" -OutputFilePath "C:\PATH\WHERE\YOU\WANT\IT\EncryptedFile.enc" -Password $PlainPassword

# Decrypt
# Decrypt-Folder -InputFilePath "C:\SAME\PATH\AS\SET\ABOVE\FOR\EncryptedFile.enc" -OutputFolderPath "C:\PATH\TO\WHERE\TO\PLACE\IT\DecryptedFolder" -Password $PlainPassword
