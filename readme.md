LOKI - Readme

To use this PowerShell script for encrypting and decrypting folders, follow these steps:

1. **Save the Script**: Save the entire script to a `.ps1` file, e.g., `EncryptDecryptScript.ps1`.

2. **Run PowerShell as Administrator**: This is necessary to install the module if it's not available.

3. **Execute the Script**: You can either run the script directly or use PowerShell ISE for interactive execution.

### Step-by-Step Instructions

#### 1. Define the Password
You will be prompted to input the password when you run the script.

```powershell
$YourPassword = Read-Host "Password is" -AsSecureString
```

#### 2. Convert the SecureString to Plain Text
This step is required for the encryption functions.

```powershell
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($YourPassword))
```

#### 3. Ensure Required Module is Available
The script checks if the `Microsoft.PowerShell.Security` module is available and installs it if necessary.

```powershell
if (-not (Get-Module -ListAvailable -Name 'Microsoft.PowerShell.Security')) {
    Install-Module -Name 'Microsoft.PowerShell.Security' -Scope CurrentUser -Force
}
```

#### 4. Define Functions
The script defines the functions `Get-EncryptedKey`, `Encrypt-Folder`, and `Decrypt-Folder`.

#### 5. Encrypt a Folder
Uncomment and run the `Encrypt-Folder` command with appropriate parameters:

```powershell
Encrypt-Folder -FolderPath "C:\Users\lco30\Documents\TestDocs" -OutputFilePath "C:\Users\lco30\Documents\EncryptedFile.enc" -Password $PlainPassword
```

- `FolderPath`: The path of the folder you want to encrypt.
- `OutputFilePath`: The path of the encrypted file.
- `Password`: The password converted to plain text.

#### 6. Decrypt a Folder
Uncomment and run the `Decrypt-Folder` command with appropriate parameters:

```powershell
Decrypt-Folder -InputFilePath "C:\Users\lco30\Documents\EncryptedFile.enc" -OutputFolderPath "C:\Users\lco30\Documents\DecryptedFolder" -Password $PlainPassword
```

- `InputFilePath`: The path of the encrypted file.
- `OutputFolderPath`: The path where the decrypted files will be stored.
- `Password`: The password converted to plain text.

### Running the Script

1. **Open PowerShell or PowerShell ISE**:
    - Right-click on PowerShell or PowerShell ISE and select "Run as Administrator".

2. **Navigate to the Script Location**:
    - Use `cd` command to navigate to the folder where `EncryptDecryptScript.ps1` is saved.
    ```powershell
    cd path\to\script\location
    ```

3. **Run the Script**:
    - Execute the script by typing:
    ```powershell
    .\EncryptDecryptScript.ps1
    ```

### Notes

- Ensure you have appropriate permissions to read/write to the specified folders and files.
- The password used for encryption and decryption must be the same.
- Always test the script with a small set of files before using it on important data to ensure it works as expected.
