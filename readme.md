LOKIv1 "Folder En/DeCryption" - Readme

Use this PowerShell script for encrypting and decrypting folders, follow these steps:

1. **Place the script somewhere you can remember on the system**

2. **Run PowerShell as Administrator**: This is necessary to install the module if it's not available.

3. **Set Execution Policy to Bypass (There are many ways but here is one I used with the quotes: "Set-ExecutionPolicy Bypass -Scope Process")** 

4. **Execute the Script**: You can either run the script directly or use PowerShell ISE for interactive execution.

### Step-by-Step Breakdown of Loki and Instructions

#### 1. Define the Password
When you start the script, you will be prompted to input the password when you run the script.
**NOTE: Do not forget this password because it will be the same for both encrypting and decrypting. If you enter the wrong password it will error out and not move forward with Decrypting. (Also this is set to only work on the Current User that runs this script. If you change users it should not work.)**

```powershell
$YourPassword = Read-Host "Password is" -AsSecureString
```

#### 2. Convert the SecureString to Plain Text
This step is required for the encryption functions. (You do not have to do anything in this. This is automatically done after you set the password.)

```powershell
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($YourPassword))
```

#### 3. It ensures if the Required Module is Available
The script checks if the `Microsoft.PowerShell.Security` module is available and installs it if necessary.

```powershell
if (-not (Get-Module -ListAvailable -Name 'Microsoft.PowerShell.Security')) {
    Install-Module -Name 'Microsoft.PowerShell.Security' -Scope CurrentUser -Force
}
```

#### 4. It then defines the three Main Functions
The script defines the functions `Get-EncryptedKey`, `Encrypt-Folder`, and `Decrypt-Folder`.

#### 5. Instructions for you to encrypt a Folder
Uncomment and run the `Encrypt-Folder` command with appropriate parameters:

```powershell
Encrypt-Folder -FolderPath "C:\Users\lco30\Documents\TestDocs" -OutputFilePath "C:\Users\lco30\Documents\EncryptedFile.enc" -Password $PlainPassword
```

- `FolderPath`: The path of the folder you want to encrypt.
- `OutputFilePath`: The path of the encrypted file.
- `Password`: The password converted to plain text.

#### 6. Instructions for decrypting the .enc Folder
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
    - Use `cd` command to navigate to the folder where `Loki.ps1` is saved.
    ```powershell
    cd path\to\script\location
    ```

3. **Run the Script**:
    - Execute the script by typing:
    ```powershell
    .\Loki.ps1
    ```

###A little couple of side notes**
- Ensure you have appropriate permissions to read/write to the specified folders and files.
- The password used for encryption and decryption must be the same.
- Always test the script with a small set of files before using it on important data to ensure it works as expected.
**Have Fun!**
