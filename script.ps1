# Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

# Needs Restart
$input = Read-Host "Restart Needed for these settings? (y/n)"

if ($input -eq 'y') {
    Write-Host "Applying settings..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
    BCDEDIT /set "{current}" nx AlwaysOn
    Set-ProcessMitigation -System -Enable DEP
    gpupdate /force
    Restart-Computer -Force
    exit
} elseif ($input -eq 'n') {
    Write-Host "Settings not applied."
} else {
    Write-Host "Invalid input. Please enter 'y' or 'n'."
    exit
}

Import-Module GroupPolicy

$GPOName = "Default Domain Policy"

# Services
Set-Service -Name "wuauserv" -StartupType Automatic; Start-Service "wuauserv"
Set-Service -Name "Dhcp" -StartupType Automatic; Start-Service "Dhcp"
Set-Service -Name "eventlog" -StartupType Automatic; Start-Service "eventlog"

# Password
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "MaximumPasswordAge" -Type DWord -Value 30
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "MinimumPasswordAge" -Type DWord -Value 1
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "MinimumPasswordLength" -Type DWord -Value 14
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "PasswordHistorySize" -Type DWord -Value 24
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "PasswordComplexity" -Type DWord -Value 1

# Lockout
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MaximumLockoutTime" -Type DWord -Value 1800
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "LockoutBadCount" -Type DWord -Value 5
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "ResetLockoutCount" -Type DWord -Value 1800

# Non-Server

secedit /export /cfg c:\secpol.cfg

(Get-Content C:\secpol.cfg) -replace "PasswordComplexity = \d+", "PasswordComplexity = 1" `
                             -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = 30" `
                             -replace "MinimumPasswordAge = \d+", "MinimumPasswordAge = 1" `
                             -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 14" `
                             -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 24" `
                             -replace "ClearTextPassword = \d+", "ClearTextPassword = 0" `
                             -replace "LockoutBadCount = \d+", "LockoutBadCount = 5" `
                             -replace "LockoutDuration = \d+", "LockoutDuration = 30" `
                             -replace "ResetLockoutCount = \d+", "ResetLockoutCount = 30" `
| Out-File C:\secpol.cfg

secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
Remove-Item C:\secpol.cfg -Force

# Audit
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

# Security
Disable-LocalUser -Name "Administrator"
Disable-LocalUser -Name "Guest"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "FullPrivilegeAuditing" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "UndockWithoutLogon" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayUserName" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableForcedLogoff" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffAnonymousBlock" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableForcedLogoff" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name "SecurityLevel" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name "SetCommand" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "StrengthenDefaultPermissions" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableUIADesktopToggle" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

Disable-PSRemoting -Force

# RT Protection (will get reset if gpedit/admin template settings are different than the registry key)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force

gpupdate /force
