#=============================================================================================================================
#
# Script Name:     HardwareReadiness.ps1
# Description:     Verifies the hardware compliance. Return code 0 for success. 
#                  In case of failure, returns non zero error code along with error message.

# This script is not supported under any Microsoft standard support program or service and is distributed under the MIT license

# Copyright (C) 2021 Microsoft Corporation

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#=============================================================================================================================

$exitCode = 0

[int]$MinOSDiskSizeGB = 64
[int]$MinMemoryGB = 4
[Uint32]$MinClockSpeedMHz = 1000
[Uint32]$MinLogicalCores = 2
[Uint16]$RequiredAddressWidth = 64

$PASS_STRING = "PASS"
$FAIL_STRING = "FAIL"
$FAILED_TO_RUN_STRING = "FAILED TO RUN"
$UNDETERMINED_CAPS_STRING = "UNDETERMINED"
$UNDETERMINED_STRING = "Undetermined"
$CAPABLE_STRING = "Capable"
$NOT_CAPABLE_STRING = "Not capable"
$CAPABLE_CAPS_STRING = "CAPABLE"
$NOT_CAPABLE_CAPS_STRING = "NOT CAPABLE"
$STORAGE_STRING = "Storage"
$OS_DISK_SIZE_STRING = "OSDiskSize"
$MEMORY_STRING = "Memory"
$SYSTEM_MEMORY_STRING = "System_Memory"
$GB_UNIT_STRING = "GB"
$TPM_STRING = "TPM"
$TPM_VERSION_STRING = "TPMVersion"
$PROCESSOR_STRING = "Processor"
$SECUREBOOT_STRING = "SecureBoot"
$I7_7820HQ_CPU_STRING = "i7-7820hq CPU"

# 0=name of check, 1=attribute checked, 2=value, 3=PASS/FAIL/UNDETERMINED
$logFormat = '{0}: {1}={2}. {3}; '

# 0=name of check, 1=attribute checked, 2=value, 3=unit of the value, 4=PASS/FAIL/UNDETERMINED
$logFormatWithUnit = '{0}: {1}={2}{3}. {4}; '

# 0=name of check.
$logFormatReturnReason = '{0}, '

# 0=exception.
$logFormatException = '{0}; '

# 0=name of check, 1= attribute checked and its value, 2=PASS/FAIL/UNDETERMINED
$logFormatWithBlob = '{0}: {1}. {2}; '

# return returnCode is -1 when an exception is thrown. 1 if the value does not meet requirements. 0 if successful. -2 default, script didn't run.
$outObject = @{ returnCode = -2; returnResult = $FAILED_TO_RUN_STRING; returnReason = ""; logging = "" }

# NOT CAPABLE(1) state takes precedence over UNDETERMINED(-1) state
function Private:UpdateReturnCode {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(-2, 1)]
        [int] $ReturnCode
    )

    switch ($ReturnCode) {

        0 {
            if ($outObject.returnCode -eq -2) {
                $outObject.returnCode = $ReturnCode
            }
        }
        1 {
            $outObject.returnCode = $ReturnCode
        }
        -1 {
            if ($outObject.returnCode -ne 1) {
                $outObject.returnCode = $ReturnCode
            }
        }
    }
}

$Source = @"
using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

    public class CpuFamilyResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }

    public class CpuFamily
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public enum ProcessorFeature : uint
        {
            ARM_SUPPORTED_INSTRUCTIONS = 34
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsProcessorFeaturePresent(ProcessorFeature processorFeature);

        private const ushort PROCESSOR_ARCHITECTURE_X86 = 0;
        private const ushort PROCESSOR_ARCHITECTURE_ARM64 = 12;
        private const ushort PROCESSOR_ARCHITECTURE_X64 = 9;

        private const string INTEL_MANUFACTURER = "GenuineIntel";
        private const string AMD_MANUFACTURER = "AuthenticAMD";
        private const string QUALCOMM_MANUFACTURER = "Qualcomm Technologies Inc";

        public static CpuFamilyResult Validate(string manufacturer, ushort processorArchitecture)
        {
            CpuFamilyResult cpuFamilyResult = new CpuFamilyResult();

            if (string.IsNullOrWhiteSpace(manufacturer))
            {
                cpuFamilyResult.IsValid = false;
                cpuFamilyResult.Message = "Manufacturer is null or empty";
                return cpuFamilyResult;
            }

            string registryPath = "HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\CentralProcessor\\0";
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetNativeSystemInfo(ref sysInfo);

            switch (processorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_ARM64:

                    if (manufacturer.Equals(QUALCOMM_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isArmv81Supported = IsProcessorFeaturePresent(ProcessorFeature.ARM_SUPPORTED_INSTRUCTIONS);

                        if (!isArmv81Supported)
                        {
                            string registryName = "CP 4030";
                            long registryValue = (long)Registry.GetValue(registryPath, registryName, -1);
                            long atomicResult = (registryValue >> 20) & 0xF;

                            if (atomicResult >= 2)
                            {
                                isArmv81Supported = true;
                            }
                        }

                        cpuFamilyResult.IsValid = isArmv81Supported;
                        cpuFamilyResult.Message = isArmv81Supported ? "" : "Processor does not implement ARM v8.1 atomic instruction";
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "The processor isn't currently supported for Windows 11";
                    }

                    break;

                case PROCESSOR_ARCHITECTURE_X64:
                case PROCESSOR_ARCHITECTURE_X86:

                    int cpuFamily = sysInfo.ProcessorLevel;
                    int cpuModel = (sysInfo.ProcessorRevision >> 8) & 0xFF;
                    int cpuStepping = sysInfo.ProcessorRevision & 0xFF;

                    if (manufacturer.Equals(INTEL_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            cpuFamilyResult.IsValid = true;
                            cpuFamilyResult.Message = "";

                            if (cpuFamily >= 6 && cpuModel <= 95 && !(cpuFamily == 6 && cpuModel == 85))
                            {
                                cpuFamilyResult.IsValid = false;
                                cpuFamilyResult.Message = "";
                            }
                            else if (cpuFamily == 6 && (cpuModel == 142 || cpuModel == 158) && cpuStepping == 9)
                            {
                                string registryName = "Platform Specific Field 1";
                                int registryValue = (int)Registry.GetValue(registryPath, registryName, -1);

                                if ((cpuModel == 142 && registryValue != 16) || (cpuModel == 158 && registryValue != 8))
                                {
                                    cpuFamilyResult.IsValid = false;
                                }
                                cpuFamilyResult.Message = "PlatformId " + registryValue;
                            }
                        }
                        catch (Exception ex)
                        {
                            cpuFamilyResult.IsValid = false;
                            cpuFamilyResult.Message = "Exception:" + ex.GetType().Name;
                        }
                    }
                    else if (manufacturer.Equals(AMD_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        cpuFamilyResult.IsValid = true;
                        cpuFamilyResult.Message = "";

                        if (cpuFamily < 23 || (cpuFamily == 23 && (cpuModel == 1 || cpuModel == 17)))
                        {
                            cpuFamilyResult.IsValid = false;
                        }
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "Unsupported Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    }

                    break;

                default:
                    cpuFamilyResult.IsValid = false;
                    cpuFamilyResult.Message = "Unsupported CPU category. Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    break;
            }
            return cpuFamilyResult;
        }
    }
"@

# Storage
try {
    $osDrive = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property SystemDrive
    $osDriveSize = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($osDrive.SystemDrive)'" | Select-Object @{Name = "SizeGB"; Expression = { $_.Size / 1GB -as [int] } }  

    if ($null -eq $osDriveSize) {
        UpdateReturnCode -ReturnCode 1
        $outObject.returnReason += $logFormatReturnReason -f $STORAGE_STRING
        $outObject.logging += $logFormatWithBlob -f $STORAGE_STRING, "Storage is null", $FAIL_STRING
        $exitCode = 1
    } elseif ($osDriveSize.SizeGB -lt $MinOSDiskSizeGB) {
        UpdateReturnCode -ReturnCode 1
        $outObject.returnReason += $logFormatReturnReason -f $STORAGE_STRING
        $outObject.logging += $logFormatWithUnit -f $STORAGE_STRING, $OS_DISK_SIZE_STRING, ($osDriveSize.SizeGB), $GB_UNIT_STRING, $FAIL_STRING
        $exitCode = 1
    } else {
        $outObject.logging += $logFormatWithUnit -f $STORAGE_STRING, $OS_DISK_SIZE_STRING, ($osDriveSize.SizeGB), $GB_UNIT_STRING, $PASS_STRING
        UpdateReturnCode -ReturnCode 0
    }
} catch {
    UpdateReturnCode -ReturnCode -1
    $outObject.logging += $logFormat -f $STORAGE_STRING, $OS_DISK_SIZE_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
    $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    $exitCode = 1
}

# Memory (bytes)
try {
    $memory = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | Select-Object @{Name = "SizeGB"; Expression = { $_.Sum / 1GB -as [int] } }

    if ($null -eq $memory) {
        UpdateReturnCode -ReturnCode 1
        $outObject.returnReason += $logFormatReturnReason -f $MEMORY_STRING
        $outObject.logging += $logFormatWithBlob -f $MEMORY_STRING, "Memory is null", $FAIL_STRING
        $exitCode = 1
    } elseif ($memory.SizeGB -lt $MinMemoryGB) {
        UpdateReturnCode -ReturnCode 1
        $outObject.returnReason += $logFormatReturnReason -f $MEMORY_STRING
        $outObject.logging += $logFormatWithUnit -f $MEMORY_STRING, $SYSTEM_MEMORY_STRING, ($memory.SizeGB), $GB_UNIT_STRING, $FAIL_STRING
        $exitCode = 1
    } else {
        $outObject.logging += $logFormatWithUnit -f $MEMORY_STRING, $SYSTEM_MEMORY_STRING, ($memory.SizeGB), $GB_UNIT_STRING, $PASS_STRING
        UpdateReturnCode -ReturnCode 0
    }
} catch {
    UpdateReturnCode -ReturnCode -1
    $outObject.logging += $logFormat -f $MEMORY_STRING, $SYSTEM_MEMORY_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
    $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    $exitCode = 1
}

# TPM
try {
    $tpm = Get-Tpm

    if ($null -eq $tpm) {
        UpdateReturnCode -ReturnCode 1
        $outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
        $outObject.logging += $logFormatWithBlob -f $TPM_STRING, "TPM is null", $FAIL_STRING
        $exitCode = 1
    } elseif ($tpm.TpmPresent) {
        $tpmVersion = Get-WmiObject -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm | Select-Object -Property SpecVersion

        if ($null -eq $tpmVersion.SpecVersion) {
            UpdateReturnCode -ReturnCode 1
            $outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
            $outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, "null", $FAIL_STRING
            $exitCode = 1
        }

        $majorVersion = $tpmVersion.SpecVersion.Split(",")[0] -as [int]
        if ($majorVersion -lt 2) {
            UpdateReturnCode -ReturnCode 1
            $outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
            $outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, ($tpmVersion.SpecVersion), $FAIL_STRING
            $exitCode = 1
        } else {
            $outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, ($tpmVersion.SpecVersion), $PASS_STRING
            UpdateReturnCode -ReturnCode 0
        }
    } else {
        if ($tpm.GetType().Name -eq "String") {
            UpdateReturnCode -ReturnCode -1
            $outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
            $outObject.logging += $logFormatException -f $tpm
        } else {
            UpdateReturnCode -ReturnCode 1
            $outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
            $outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, ($tpm.TpmPresent), $FAIL_STRING
        }
        $exitCode = 1
    }
} catch {
    UpdateReturnCode -ReturnCode -1
    $outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
    $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    $exitCode = 1
}

# CPU Details
$cpuDetails
try {
    $cpuDetails = @(Get-WmiObject -Class Win32_Processor)[0]

    if ($null -eq $cpuDetails) {
        UpdateReturnCode -ReturnCode 1
        $exitCode = 1
        $outObject.returnReason += $logFormatReturnReason -f $PROCESSOR_STRING
        $outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, "CpuDetails is null", $FAIL_STRING
    } else {
        $processorCheckFailed = $false

        # AddressWidth
        if ($null -eq $cpuDetails.AddressWidth -or $cpuDetails.AddressWidth -ne $RequiredAddressWidth) {
            UpdateReturnCode -ReturnCode 1
            $processorCheckFailed = $true
            $exitCode = 1
        }

        # ClockSpeed is in MHz
        if ($null -eq $cpuDetails.MaxClockSpeed -or $cpuDetails.MaxClockSpeed -le $MinClockSpeedMHz) {
            UpdateReturnCode -ReturnCode 1
            $processorCheckFailed = $true
            $exitCode = 1
        }

        # Number of Logical Cores
        if ($null -eq $cpuDetails.NumberOfLogicalProcessors -or $cpuDetails.NumberOfLogicalProcessors -lt $MinLogicalCores) {
            UpdateReturnCode -ReturnCode 1
            $processorCheckFailed = $true
            $exitCode = 1
        }

        # CPU Family
        Add-Type -TypeDefinition $Source
        $cpuFamilyResult = [CpuFamily]::Validate([String]$cpuDetails.Manufacturer, [uint16]$cpuDetails.Architecture)

        $cpuDetailsLog = "{AddressWidth=$($cpuDetails.AddressWidth); MaxClockSpeed=$($cpuDetails.MaxClockSpeed); NumberOfLogicalCores=$($cpuDetails.NumberOfLogicalProcessors); Manufacturer=$($cpuDetails.Manufacturer); Caption=$($cpuDetails.Caption); $($cpuFamilyResult.Message)}"

        if (!$cpuFamilyResult.IsValid) {
            UpdateReturnCode -ReturnCode 1
            $processorCheckFailed = $true
            $exitCode = 1
        }

        if ($processorCheckFailed) {
            $outObject.returnReason += $logFormatReturnReason -f $PROCESSOR_STRING
            $outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, ($cpuDetailsLog), $FAIL_STRING
        } else {
            $outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, ($cpuDetailsLog), $PASS_STRING
            UpdateReturnCode -ReturnCode 0
        }
    }
} catch {
    UpdateReturnCode -ReturnCode -1
    $outObject.logging += $logFormat -f $PROCESSOR_STRING, $PROCESSOR_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
    $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    $exitCode = 1
}

# SecureBooot
try {
    $isSecureBootEnabled = Confirm-SecureBootUEFI
    $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $CAPABLE_STRING, $PASS_STRING
    UpdateReturnCode -ReturnCode 0
} catch [System.PlatformNotSupportedException] {
    # PlatformNotSupportedException "Cmdlet not supported on this platform." - SecureBoot is not supported or is non-UEFI computer.
    UpdateReturnCode -ReturnCode 1
    $outObject.returnReason += $logFormatReturnReason -f $SECUREBOOT_STRING
    $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $NOT_CAPABLE_STRING, $FAIL_STRING
    $exitCode = 1
} catch [System.UnauthorizedAccessException] {
    UpdateReturnCode -ReturnCode -1
    $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
    $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    $exitCode = 1
} catch {
    UpdateReturnCode -ReturnCode -1
    $outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
    $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    $exitCode = 1
}

# i7-7820hq CPU
try {
    $supportedDevices = @('surface studio 2', 'precision 5520')
    $systemInfo = @(Get-WmiObject -Class Win32_ComputerSystem)[0]

    if ($null -ne $cpuDetails) {
        if ($cpuDetails.Name -match 'i7-7820hq cpu @ 2.90ghz') {
            $modelOrSKUCheckLog = $systemInfo.Model.Trim()
            if ($supportedDevices -contains $modelOrSKUCheckLog) {
                $outObject.logging += $logFormatWithBlob -f $I7_7820HQ_CPU_STRING, $modelOrSKUCheckLog, $PASS_STRING
                $outObject.returnCode = 0
                $exitCode = 0
            }
        }
    }
} catch {
    if ($outObject.returnCode -ne 0) {
        UpdateReturnCode -ReturnCode -1
        $outObject.logging += $logFormatWithBlob -f $I7_7820HQ_CPU_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
        $outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
        $exitCode = 1
    }
}

switch ($outObject.returnCode) {

    0 { $outObject.returnResult = $CAPABLE_CAPS_STRING }
    1 { $outObject.returnResult = $NOT_CAPABLE_CAPS_STRING }
    -1 { $outObject.returnResult = $UNDETERMINED_CAPS_STRING }
    -2 { $outObject.returnResult = $FAILED_TO_RUN_STRING }
}

#$outObject | ConvertTo-Json -Compress

if ($outObject.returnResult -eq $CAPABLE_CAPS_STRING) {
    $WIN11COMPATIBLE = $true
} else {
    $WIN11COMPATIBLE = $false
}

[pscustomobject]@{
    WIN11COMPATIBLE   = $WIN11COMPATIBLE
    IncompatibleItems = $outObject.returnReason
}
# SIG # Begin signature block
# MIIjgwYJKoZIhvcNAQcCoIIjdDCCI3ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBiHhm0Lk+/A8qC
# V96ruzLc51r2jcv0Tmi4ylIArUm6AaCCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWDCCFVQCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgDitXJ5WN
# blV7Vpa8S/1rP1RiKAYCi9M7QPX4/HQ3y4cwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQDJnb0Gp/dxyc1nlHUducMqatVAd89yxAodlVziyyKO
# +Y+vimn+0UH+eKuz0QINAL+TtbZBtbmhmtwv71H1D7j0Nc5M4YXe5kTtgHttYTcw
# vqF9LIlIDOf0A/v7NoUTb5rTtgpi4xOOfY2RIDW3THTMeazZbAqA/5bUzD4v0sq6
# HQp+FvdVbrA+f88mgiKiWZEroIdfpug92JYa2+7B49CzcyqePj4Rq0qOZfZZZTHj
# Du5b7SSTc//pSV7vJxs3FMtuv1IJ8aVylAiocfiy0zQePiGINfEOdvMga/wm231s
# O4QPSkEYOaocbbonuoGc7i5vzDuLgNFkvFKQ6HFmaXtNoYIS4jCCEt4GCisGAQQB
# gjcDAwExghLOMIISygYJKoZIhvcNAQcCoIISuzCCErcCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIMi6knq2c/5TFRmh2ovvKUeL0O+wObeRcMIt3jix
# W5NpAgZhkuFbwjYYEzIwMjExMTI5MTkzODIwLjk3MVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOTCCBPEwggPZoAMCAQICEzMAAAFSMEtdiazmcEcAAAAAAVIw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNjA1WhcNMjIwMjExMTgyNjA1WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEy
# NUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuzG6EiZh0taCSbswMiupMTYnbboFz
# jj1DuDbbvT0RXKBCVl/umA+Uy214DmHiFhkeuRdlLB0ya5S9um5aKr7lBBqZzvtK
# gGNgCRbDTG9Yu6kzDzPTzQRulVIvoWVy0gITnEyoJ1O3m5IPpsLBNQCdXsh+3TZF
# 73JAcub21bnxm/4sxe4zTdbdttBrqX8/JJF2VEnAP+MBvF2UQSo6XUAaTKC/HPDP
# Cce/IsNoAxxLDI1wHhIlqjRBnt4HM5HcKHrZrvH+vHnihikdlEzh3fjQFowk1fG7
# PVhmO60O5vVdqA+H9314hHENQI0cbo+SkSi8SSJSLNixgj0eWePTh7pbAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUhN2u2qwj1l2c2h/kULDuBRJsexQwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAVcUncfFqSazQbDEXf3d10/upiWQU5HdTbwG9v9be
# VIDaG4oELyIcNE6e6CbOBMlPU+smpYYcnK3jucNqChwquLmxdi2iPy4iQ6vjAdBp
# 9+VFWlrBqUsNXZzjCpgMCZj6bu8Xq0Nndl4WyBbI0Jku68vUNG4wsMdKP3dz+1Mz
# k9SUma3j7HyNA559do9nhKmoZMn5dtf03QvxlaEwMAaPk9xuUv9BN8cNvFnpWk4m
# LERQW6tA3rXK0soEISKTYG7Ose7oMXZDYPWxf9oFhYKzZw/SwnhdBoj2S5eyYE3A
# uF/ZXzR3hdp3/XGzZeOdERfFy1rC7ZBwhDIajeFMi53GnzCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAv26eVJaumcmTchd6hqayQMNDXluggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOVPK8owIhgPMjAy
# MTExMjkxODM2NThaGA8yMDIxMTEzMDE4MzY1OFowdDA6BgorBgEEAYRZCgQBMSww
# KjAKAgUA5U8rygIBADAHAgEAAgIIDjAHAgEAAgIRNjAKAgUA5VB9SgIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBAKSuH0noJnIFtg5RpXDvWNLW+huGUoi5rQao
# Q/hD3bgUS5Cz3Uryf8a0+7rPTgb3JP2BRqRmaOV96v1IOlvkTZvn6Rkzn/CcGYke
# CT1m5tuqQxu1og1btZ/I46qkqBuA3yNLvZXeFacSYcPThm0i57Da+ZI9cD5M+0ao
# AfNpGZaxMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAFSMEtdiazmcEcAAAAAAVIwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgGscj0u+qkYw/
# L5wuBz+kdHOb+1eO9L0pqsxwdEewuNIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCCT7lzHo4slUIxfEGp8LXQNik/ecK6vuuGWIcmBrrsnpjCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABUjBLXYms5nBHAAAAAAFS
# MCIEIFWlZTc/9zaNk0I+M/tMVCCoIzM871wIWLO7b1YNXbfkMA0GCSqGSIb3DQEB
# CwUABIIBAIIb/rygBUgyQEFXSYOEOa3hEayOa+xIccSsCJ7LSoMqQOnVy/Jq3kvk
# Fk0PcJK1xpazk97uaDPFh2WBzTNjw8dOh7R6xuKkBJuDW00JEow1sJujmi1ioVe5
# NoBzusX22S/I5HSlODMpspTmQ7ol9RSHYKJFVCBavKyhiVNXxftFuxfmGaGG8c7m
# fSIivdGEapkSeePWzBNgf6JzozrCZoBNHxCKYiwjLTqEG0Aj1WBH8AvpZKVh8m13
# HGEDSbyAEi/LzoDmviMSCyHXO8TQ9l23hSkKpd/Ui1+nNeQjMI4USj7O1vVGKo2z
# ExFPbq21sdZKYgarUsL4JFHyCI6PMaw=
# SIG # End signature block