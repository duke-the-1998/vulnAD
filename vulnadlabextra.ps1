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

# Função para habilitar WinRM em todos os hosts do domínio
function Enable-WinRMOnDomainHosts {
    Write-Output "A ativar WinRM (Windows Remote Management) em todos os hosts do dominio"
    
    # Verifica se o módulo Active Directory está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Output "O madulo Active Directory nao esta disponível. Instalando o modulo"
        Install-WindowsFeature -Name RSAT-AD-PowerShell
        Import-Module ActiveDirectory
    }

    # Obter todos os computadores no domínio
    $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    # Loop para habilitar WinRM em cada computador
    foreach ($computer in $computers) {
        Write-Output "A habilitar WinRM no host: $computer"
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock {
                Write-Output "Habilitanr e configurar WinRM"
                Enable-PSRemoting -Force
                Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
                Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
                Write-Output "WinRM habilitado com sucesso."
            } -Credential (Get-Credential) -ErrorAction Stop
        } catch {
            Write-Output "Falha ao configurar WinRM no host: $computer. Erro: $_"
        }
    }
}

# Função para habilitar RDP em todos os hosts do domínio
function Enable-RDPOnDomainHosts {
    Write-Output "Ativar RDP (Remote Desktop Protocol) em todos os hosts do dominio"
    
    # Verifica se o módulo Active Directory está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Output "O modulo Active Directory nao esta disponivel. Instalar o modulo"
        Install-WindowsFeature -Name RSAT-AD-PowerShell
        Import-Module ActiveDirectory
    }

    # Obter todos os computadores no domínio
    $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    # Loop para habilitar RDP em cada computador
    foreach ($computer in $computers) {
        Write-Output "Habilitar RDP no host: $computer"
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock {
                Write-Output "A configurar RDP"
                
                # Permitir conexões RDP
                Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
                
                # Configurar firewall para permitir RDP
               # Write-Output "ConfigurarFirewall para permitir conexões RDP..."
               # Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
                
              #  Write-Output "RDP habilitado com sucesso."
            } -Credential (Get-Credential) -ErrorAction Stop
        } catch {
            Write-Output "Falha ao configurar RDP no host: $computer. Erro: $_"
        }
    }
}

# Função para habilitar RPC em todos os hosts do domínio
function Enable-RPCOnDomainHosts {
    Write-Output "Ativando RPC (Remote Procedure Call) em todos os hosts do domínio..."
    
    # Verifica se o módulo Active Directory está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Output "O módulo Active Directory não está disponível. Instalando o módulo..."
        Install-WindowsFeature -Name RSAT-AD-PowerShell
        Import-Module ActiveDirectory
    }

    # Obter todos os computadores no domínio
    $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    # Loop para habilitar RPC em cada computador
    foreach ($computer in $computers) {
        Write-Output "Habilitando RPC no host: $computer"
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock {
                Write-Output "Configurando RPC..."

                # Certifique-se de que o serviço RPC (Remote Procedure Call) está ativado
                Set-Service -Name "RpcSs" -StartupType Automatic
                Start-Service -Name "RpcSs"
                
                # Habilitar regras de firewall para permitir tráfego RPC
                Write-Output "Configurando Firewall para permitir tráfego RPC..."
                Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"
                Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
                
                Write-Output "RPC habilitado com sucesso."
            } -Credential (Get-Credential) -ErrorAction Stop
        } catch {
            Write-Output "Falha ao configurar RPC no host: $computer. Erro: $_"
        }
    }
}

# Função para desabilitar a assinatura SMB em todos os hosts do domínio
function Disable-SMBSigningOnDomainHosts {
    Write-Output "Desativando a Assinatura SMB em todos os hosts do domínio..."
    
    # Verifica se o módulo Active Directory está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Output "O módulo Active Directory não está disponível. Instalando o módulo..."
        Install-WindowsFeature -Name RSAT-AD-PowerShell
        Import-Module ActiveDirectory
    }

    # Obter todos os computadores no domínio
    $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    # Loop para desabilitar a assinatura SMB em cada computador
    foreach ($computer in $computers) {
        Write-Output "Desativando a assinatura SMB no host: $computer"
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock {
                Write-Output "Configurando SMB para desativar a assinatura..."

                # Desabilita a assinatura SMB para clientes
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 0 -Force

                # Desabilita a assinatura SMB para servidores
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 0 -Force
                
                Write-Output "Assinatura SMB desativada com sucesso."
            } -Credential (Get-Credential) -ErrorAction Stop
        } catch {
            Write-Output "Falha ao desativar a assinatura SMB no host: $computer. Erro: $_"
        }
    }
}

# Função para habilitar SSL/LDAP em todos os hosts do domínio
function Enable-SSL_LDAPOnDomainHosts {
    Write-Output "Ativando SSL/LDAP (LDAPS) em todos os hosts do domínio..."

    # Verifica se o módulo Active Directory está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Output "O módulo Active Directory não está disponível. Instalando o módulo..."
        Install-WindowsFeature -Name RSAT-AD-PowerShell
        Import-Module ActiveDirectory
    }

    # Obter todos os controladores de domínio no domínio
    $domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

    # Loop para habilitar SSL/LDAP em cada controlador de domínio
    foreach ($dc in $domainControllers) {
        Write-Output "Configurando SSL/LDAP no controlador de domínio: $dc"
        try {
            Invoke-Command -ComputerName $dc -ScriptBlock {
                Write-Output "Configurando LDAP para usar SSL..."

                # Instalar o certificado SSL no controlador de domínio
                Write-Output "Certifique-se de que há um certificado SSL válido instalado para LDAPS."
                
                # Habilitar LDAPS (implica que o certificado SSL está configurado)
                # Configuração do Firewall para permitir tráfego LDAPS na porta 636
                Write-Output "Configurando Firewall para permitir LDAPS..."
                New-NetFirewallRule -DisplayName "Allow LDAPS" -Direction Inbound -Protocol TCP -LocalPort 636 -Action Allow
                
                Write-Output "SSL/LDAP (LDAPS) configurado com sucesso."
            } -Credential (Get-Credential) -ErrorAction Stop
        } catch {
            Write-Output "Falha ao configurar SSL/LDAP no controlador de domínio: $dc. Erro: $_"
        }
    }
}

# Função para habilitar WinRM (RPC sobre HTTP/1.1) em todos os hosts do domínio
function Enable-RPCOverHTTPOnDomainHosts {
    Write-Output "Ativando WinRM (RPC sobre HTTP/1.1) em todos os hosts do domínio..."

    # Verifica se o módulo Active Directory está disponível
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Output "O módulo Active Directory não está disponível. Instalando o módulo..."
        Install-WindowsFeature -Name RSAT-AD-PowerShell
        Import-Module ActiveDirectory
    }

    # Obter todos os computadores no domínio
    $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    # Loop para habilitar WinRM (RPC sobre HTTP) em cada computador
    foreach ($computer in $computers) {
        Write-Output "Configurando WinRM (RPC sobre HTTP) no host: $computer"
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock {
                Write-Output "Configurando WinRM para aceitar conexões HTTP..."
                
                # Habilita WinRM
                Enable-PSRemoting -Force
                
                # Configura WinRM para permitir conexões HTTP não criptografadas (inseguro)
                Write-Output "Configurando WinRM para permitir conexões HTTP não criptografadas..."
                Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
                
                # Configurar firewall para permitir conexões na porta 5985 (HTTP)
                Write-Output "Configurando Firewall para permitir tráfego HTTP (porta 5985)..."
                New-NetFirewallRule -Name "Allow WinRM HTTP" -DisplayName "Allow WinRM HTTP" -Protocol TCP -LocalPort 5985 -Action Allow
                
                Write-Output "WinRM (RPC sobre HTTP) configurado com sucesso."
            } -Credential (Get-Credential) -ErrorAction Stop
        } catch {
            Write-Output "Falha ao configurar WinRM (RPC sobre HTTP) no host: $computer. Erro: $_"
        }
    }
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
    Enable-WinRMOnDomainHosts
    Enable-RDPOnDomainHosts
    Enable-RPCOnDomainHosts
    Disable-SMBSigningOnDomainHosts
    Enable-SSL_LDAPOnDomainHosts
    Enable-RPCOverHTTPOnDomainHosts
    Start-Sleep 30; Restart-Computer
}

main
