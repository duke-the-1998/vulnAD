# habilitar SMBv1
function Enable-SMBv1 {
    Write-Output "Ativar SMBv1 (vulneravel)"
    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
}

# habilitar LDAP não seguro
function Enable-InsecureLDAP {
    Write-Output "Ativar LDAP vulneravel"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 0 -Force
}

# verificar e ativar o serviço DNS
function Enable-DNS {
    Write-Output "A verificar servico DNS..."
    $dnsStatus = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
    if ($dnsStatus -eq $null) {
        Write-Output "O serviço DNS nao esta instalado. A instalar o servico DNS"
        Install-WindowsFeature -Name DNS -IncludeManagementTools
        Start-Service -Name "DNS"
    } else {
        Write-Output "O servico DNS esta instalado. A verificar status"
        if ($dnsStatus.Status -ne "Running") {
            Write-Output "O servico DNS nao esta ativo. A iniciar servico DNS"
            Start-Service -Name "DNS"
        } else {
            Write-Output "Servico DNS ativo."
        }
    }
}

#  habilitar RDP
function Enable-RDP {
    Write-Output "Ativar RDP (Remote Desktop Protocol)"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

# habilitar Telnet
function Enable-Telnet {
    Write-Output "Ativar Telnet"
    Install-WindowsFeature -Name Telnet-Client, Telnet-Server
    Start-Service -Name "TlntSvr"
    Set-Service -Name "TlntSvr" -StartupType Automatic
}

# habilitar FTP
function Enable-FTP {
    Write-Output "Ativar FTP "
    Install-WindowsFeature -Name Web-Ftp-Server -IncludeManagementTools
    Set-Service -Name "FTPSVC" -StartupType Automatic
    Start-Service -Name "FTPSVC"
}

# Função para configurar HTTP sem HTTPS no IIS
function Enable-InsecureHTTP {
    Write-Output "Configurar servidor HTTP sem HTTPS"
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    Start-Service -Name "W3SVC"
    # Configuração simples para HTTP sem HTTPS no IIS
    New-Item -Path "IIS:\Sites\Default Web Site" -Name "InsecureSite" -PhysicalPath "C:\inetpub\wwwroot" -BindingInformation "*:80:"
}

# habilitar SNMP v2c inseguro
function Enable-SNMPv2c {
    Write-Output "Ativar SNMP v2c"
    Install-WindowsFeature -Name SNMP-Service
    Set-Service -Name "SNMP" -StartupType Automatic
    Start-Service -Name "SNMP"
    
    # Configurar SNMP para v2c
    Write-Output "Configurar SNMP para v2c"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "public" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration" -Name "public" -Value "127.0.0.1" -Force
}

# ativar NetBIOS sobre TCP/IP
function Enable-NetBIOS {
    Write-Output "Ativar NetBIOS sobre TCP/IP"
    Get-NetAdapter | Set-NetIPInterface -NetBIOS Enable
}

# ativar Impressão Remota via SMB
function Enable-RemotePrinting {
    Write-Output "Ativar Impressão Remota (SMB)"
    Set-Service -Name "Spooler" -StartupType Automatic
    Start-Service -Name "Spooler"
}

# Main
function main {
    Enable-SMBv1
    Enable-InsecureLDAP
    Enable-DNS
    Enable-RDP
    #Enable-Telnet
    Enable-FTP
    Enable-InsecureHTTP
    Enable-SNMPv2c
    Enable-NetBIOS
    Enable-RemotePrinting
    Start-Sleep 30; Restart-Computer
}

main
