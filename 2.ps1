# ====================
# GENERAL CONFIGURATION
# ====================

# Sets the execution policy to bypass restrictions for the current user.
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

# Prompts user for a restart to apply DEP and LSA Protection changes.
$input = Read-Host "Restart for DEP and LSA Protection? (y/n)"

if ($input -eq 'y') {
    Write-Host "Applying settings..."

    # Enables LSA (Local Security Authority) to run as a Protected Process Light (PPL).
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord

    # Enables Data Execution Prevention (DEP) at boot.
    BCDEDIT /set "{current}" nx AlwaysOn

    # Enforces DEP system-wide via process mitigations.
    Set-ProcessMitigation -System -Enable DEP

    # Forces Microsoft Defender Antivirus to use a sandbox for protection.
    setx /M MP_FORCE_USE_SANDBOX 1

    # Forces a Group Policy update.
    gpupdate /force

    # Restarts the computer to apply settings.
    Restart-Computer -Force
    exit
} elseif ($input -eq 'n') {
    Write-Host "Settings not applied."
} else {
    Write-Host "Invalid input. Please enter 'y' or 'n'."
    exit
}

# Imports the Group Policy module to manage GPO settings.
Import-Module GroupPolicy

$GPOName = "Default Domain Policy"

# ====================
# SERVICE CONFIGURATION
# ====================

# Starts Windows Defender Firewall (MpsSvc) service and sets it to Automatic startup.
Set-Service -Name "MpsSvc" -StartupType Automatic; Start-Service -Name "MpsSvc"

# Starts and sets services to Automatic startup.
Set-Service -Name "wuauserv" -StartupType Automatic; Start-Service "wuauserv"
Set-Service -Name "Dhcp" -StartupType Automatic; Start-Service "Dhcp"
Set-Service -Name "eventlog" -StartupType Automatic; Start-Service "eventlog"

# Disables the Print Spooler service to mitigate PrintNightmare vulnerabilities.
Set-Service -Name Spooler -StartupType Disabled; Stop-Service -Name Spooler -Force

# ====================
# FIREWALL SETTINGS
# ====================

# Sets the firewall to block all inbound traffic on the public network profile.
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block

# ====================
# PASSWORD POLICIES
# ====================

# Sets password policies: 
# Maximum password age (30 days), Minimum password age (1 day), Minimum password length (14 characters), 
# Password history size (24 previous passwords remembered), Enforces password complexity.
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "MaximumPasswordAge" -Type DWord -Value 30
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "MinimumPasswordAge" -Type DWord -Value 1
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "MinimumPasswordLength" -Type DWord -Value 14
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "PasswordHistorySize" -Type DWord -Value 24
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "PasswordComplexity" -Type DWord -Value 1

# ====================
# ACCOUNT LOCKOUT POLICIES
# ====================

# Configures account lockout policies:
# Maximum lockout time (30 minutes), Account lockout threshold (5 attempts),
# Reset lockout counter after 30 minutes.
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MaximumLockoutTime" -Type DWord -Value 1800
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "LockoutBadCount" -Type DWord -Value 5
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "ResetLockoutCount" -Type DWord -Value 1800

# ====================
# LDAP AND SECURITY SETTINGS
# ====================

# Configures LDAP server and client integrity to require signing:
# "Require signing" ensures LDAP communications are signed for integrity.
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LDAPServerIntegrity" -Type DWord -Value 2
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LDAP\Parameters" -ValueName "LDAPClientIntegrity" -Type DWord -Value 2

# Configures system auditing and privilege auditing.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "FullPrivilegeAuditing" -Value 1

# Requires LDAP client signing for security.
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 2 -Force

# Requires LDAP server integrity (signing).
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Force

# Configures Netlogon to require secure channels and disallow password changes over non-secure channels.
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1 -Force

# Configures various LSA security policies:
# These settings restrict anonymous access, disable LM hashes, and enforce stronger password and credential policies.
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "TurnOffAnonymousBlock" -Value 0 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Force
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Force

# ====================
# AUDITING POLICIES
# ====================

# Enables auditing of both success and failure events for all audit categories.
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

# ====================
# SECURITY POLICY EXPORT/CONFIGURATION
# ====================

# Exports current security policy to a configuration file.
secedit /export /cfg c:\secpol.cfg

# Updates security policies in the config file with the specified settings.
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

# Applies the updated security policies from the configuration file.
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY

# Deletes the temporary security policy configuration file.
Remove-Item C:\secpol.cfg -Force

# ====================
# WINDOWS DEFENDER CONFIGURATION
# ====================

# Configures Windows Defender Antivirus settings, including DNS sinkhole, script scanning, attack surface reduction rules, and real-time monitoring settings.
Set-MpPreference -EnableDnsSinkhole $true

# Ensures that real-time protection and anti-spyware features are enabled in Windows Defender.
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force

# Configures Windows Defender to disable macro execution from Win32 Office applications and adds attack surface reduction rules.
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled

# Enables additional attack surface reduction rules for Windows Defender.
Set-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled

# ====================
# OTHER SECURITY SETTINGS
# ====================

# Disables LM hash storage for passwords less than 15 characters.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null

# Configures NTLM compatibility to require stronger NTLMv2 authentication.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null

# Disables plaintext credential storage in WDigest.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null

# Enables UAC for remote local accounts.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null

# Enables LSASS process auditing.
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null

# Forces a Group Policy update to apply all changes.
gpupdate /force
