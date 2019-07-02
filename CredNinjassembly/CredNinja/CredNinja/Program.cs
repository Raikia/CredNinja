using System; //Console.WriteLine
using System.Collections; //ArrayList
using System.Collections.Generic;
using clipr; //Args and stuff 
using System.Diagnostics; //ProductVersion for GetOS
using System.IO; //GetDirectories
using System.Runtime.InteropServices; //WNet functions
using System.Threading;

namespace CredNinja
{
    public class Options
    {
        [NamedArgument("hosts", Description = "The hostnames to attempt to authenticate to in a comma-delimited list.", Required = true)]
        public string hosts { get; set; }

        [NamedArgument("creds", Description = "The credentials to use to attempt to authenticate as in a comma-delimited list. The proper format for this is \"DOMAIN\\Username:Password\"", Required = true)]
        public string creds { get; set; }

        [NamedArgument("scan", Description = "Switch, if enabled it will test connection to port 445 for each host before trying to authenticate. Default False.", Constraint = NumArgsConstraint.Optional, Const = true, Required = false)]
        public bool scan { get; set; }

        [NamedArgument("users", Description = "Switch, if enabled will list the users that have logged in to the system in the last 6 months (requires LOCAL ADMIN). Returns usernames with the number of days since their home directory was changed. Default false.", Constraint = NumArgsConstraint.Optional, Const = true, Required = false)]
        public bool users { get; set; }

        [NamedArgument("os", Description = "Switch, if enabled will display the OS of the system if available. Default false. ", Constraint = NumArgsConstraint.Optional, Const = true, Required = false)]
        public bool os { get; set; }

        [NamedArgument("valid", Description = "Only print valid/local admin credentials. Default false.", Constraint = NumArgsConstraint.Optional, Const = true, Required = false)]
        public bool valid { get; set; }

        [NamedArgument("invalid", Description = "Only print invalid credentials. Default false.", Constraint = NumArgsConstraint.Optional, Const = true, Required = false)]
        public bool invalid { get; set; }

        [NamedArgument("scantimeout", Description = "If given, this will set the timeout for the port scan attempt. Default is 500. Units in ms.", Required = false)]
        public int scan_timeout { get; set; }

        [NamedArgument("delay", Description = "Delay each request per thread by specified seconds", Required = false)]
        public int delay { get; set; }

        [NamedArgument("timeout", Description = "***NOT IMPLEMENTED***", Required = false)]
        public int timeout { get; set; }

        [NamedArgument("userstime", Description = "Modifies --users to search for users that have logged in within the last supplied amount of days (default 100 days)", Required = false)]
        public int users_time { get; set; }

        [NamedArgument("delim", Description = "If given, this will change the delimiter between usernames and passwords. Default is \":\".", Required = false)]
        public char delim { get; set; }

        [NamedArgument('o', "output", Description = "File/filepath to output results. This isn't error checked so be careful.", Required = false)]
        public string output { get; set; }

        [NamedArgument("threads", Description = "Number of threads to use. Defaults to 10.", Required = false)]
        public int threads { get; set; }


        public Options()
        {
            this.creds = null;
            this.hosts = null;
            this.delim = ':';
            this.output = null;
            this.scan = false;
            this.users = false;
            this.os = false;
            this.valid = false;
            this.invalid = false;
            this.scan_timeout = 500;
            this.delay = 0;
            this.timeout = 15;
            this.users_time = 100;
            this.threads = 10;
        }
    }

    public class Ninja
    {
        //Global variables
        static int workingCounter = 0;
        static int processedCounter = 0;
        const UInt32 USE_FORCE = 2;
        static object writeLockObj = new object();

        //Definitions
        public enum Status
        {
            ACCESS_DENIED = 5,
            ACCOUNT_EXPIRED = 1793,
            ACCOUNT_LOCKED_OUT = 1909,
            BAD_NETWORK_NAME = 53,
            INVALID_CREDS = 1326,
            INVALID_PASSWORD = 86,
            NO_LOGON_SERVERS = 1311,
            RPC_UNAVAILABLE = 1722,
            DUPLICATE_CONNECTION = 1219,
            SUCCESS = 0
        };

        [DllImport("NetApi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint NetUseAdd(
            string UncServerName,
            UInt32 Level,
            ref USE_INFO_2 Buf,
            out UInt32 ParmError
            );

        [DllImport("NetApi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint NetUseDel(
            string UncServerName,
            string UseName,
            UInt32 ForceCond
            );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USE_INFO_2
        {
            public string ui2_local;
            public string ui2_remote;
            public string ui2_password;
            public UInt32 ui2_status;
            public UInt32 ui2_asg_type;
            public UInt32 ui2_refcount;
            public UInt32 ui2_usecount;
            public string ui2_username;
            public string ui2_domainname;
        }

        //Actual CredNinja stuff
        static public void Exec(string[] raw_hosts, string[] raw_credentials, char delim, bool getusers, double userstime, bool valid, bool invalid, bool getos, string output, int threads, int delay)
        {
            ConsoleColor defaultColor = Console.ForegroundColor;
            //Declarations 
            Console.ForegroundColor = ConsoleColor.White;
            processedCounter = 0;
            string header, divider;

            //Decide which table header
            if (getusers || getos)
            {
                header = String.Format("{0,-20}{1,-25}{2,-20}{3,-20}{4,-20}", "Host", "Username", "Password", "Result", "Info");
                divider = String.Format("--------------------------------------------------------------------------------------------------------------------");
            }
            else
            {
                header = String.Format("{0,-20}{1,-25}{2,-20}{3,-20}", "Host", "Username", "Password", "Result");
                divider = String.Format("-------------------------------------------------------------------------------------------");
            }

            //Write header
            Console.WriteLine("");
            Console.WriteLine(header);
            Console.WriteLine(divider);
            // Unique both raw_hosts and raw_credentials
            string[] hosts;
            string[] credentials;
            List<String> tempArr = new List<string>();
            for (int i = 0; i < raw_hosts.Length; i++)
            {
                if (tempArr.Contains(raw_hosts[i]) == false)
                {
                    tempArr.Add(raw_hosts[i]);
                }
            }
            hosts = tempArr.ToArray();
            tempArr = new List<string>();
            for (int i = 0; i < raw_credentials.Length; i++)
            {
                if (tempArr.Contains(raw_credentials[i]) == false)
                {
                    tempArr.Add(raw_credentials[i]);
                }
            }
            credentials = tempArr.ToArray();
            //Check each host threaded 
            threads = Math.Min(threads, hosts.Length);
            int noDelimCreds = 0;
            foreach (string cred in credentials)
            {
                if (cred.IndexOf(delim) == -1)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("ERROR: Credential \"" + cred + "\" does not contain delimiter \"" + delim + "\"");
                    noDelimCreds += 1;
                }
            }
            if (noDelimCreds > 0)
            {
                Console.ForegroundColor = defaultColor;
                return;
            }


            //Check all hosts for a given cred asynchronously
            foreach (string cred in credentials)
            {
                if (cred.IndexOf(delim) >= 0)
                {
                    foreach (string cname in hosts)
                    {
                        //Limit number of currently running threads 
                        while (workingCounter >= threads)
                        {
                            Thread.Sleep(100);
                        }

                        //Delay if master tells Dobby to delay
                        if (delay > 0)
                        {
                            Thread.Sleep(delay * 1000);
                        }

                        workingCounter += 1;
                        ThreadStart threadDelegate = delegate { GetHost(cname, cred.Split(delim)[0], cred.Split(delim)[1], getusers, userstime, valid, invalid, getos, output); };
                        Thread th = new Thread(threadDelegate);
                        th.Start();
                    }

                    //But check each cred synchronously to prevent Error 1219
                    while (workingCounter >= 1)
                    {
                        Thread.Sleep(100);
                    }
                }
            }

            int checkCount = (hosts.Length * credentials.Length);
            while (processedCounter < checkCount)
            {
                Thread.Sleep(100);
            }

            Console.ForegroundColor = defaultColor;
            Console.WriteLine(" ");
        }

        static public void GetHost(string cname, string uname, string pword, bool getusers, double userstime, bool valid, bool invalid, bool getos, string output)
        {
            //Attempt connection
            string target = "\\\\" + cname + "\\C$";
            string username = uname;
            string domain = "";
            if (uname.IndexOf('\\') >= 0)
            {
                domain = uname.Split('\\')[0];
                username = uname.Split('\\')[1];
            }
            USE_INFO_2 info1 = new USE_INFO_2();
            info1.ui2_local = null;
            info1.ui2_asg_type = 0xFFFFFFFF;
            info1.ui2_remote = target;
            info1.ui2_username = username;
            info1.ui2_password = pword;
            info1.ui2_domainname = domain;
            uint paramErrorIndex;
            uint conn;
            uint disconn;
            int attempt = 0;
            do
            {
                lock (cname)
                {
                    conn = NetUseAdd(null, 2, ref info1, out paramErrorIndex);
                    disconn = NetUseDel(null, target, USE_FORCE);
                }
                if (attempt > 0)
                {
                    Thread.Sleep(2000 * attempt);
                }
                attempt += 1;
            }
            while (conn == (int)Status.DUPLICATE_CONNECTION && attempt < 5);
            string result = "Unknown";
            string info = "";
            //Determine connection status
            switch (conn)
            {
                case (int)Status.SUCCESS:
                    result = "LOCAL ADMIN!";

                    //Do other fun enumeration
                    if (getusers)
                        info += "(users=" + String.Join(", ", (string[])GetUsers(target, userstime).ToArray(typeof(string))) + ")";

                    if (getos)
                        info += "(os=" + GetOS(target) + ")";

                    if (disconn != 0)
                        info += "(warning=Could not disconnect drive. Finish manually.)";

                    break;
                case (int)Status.ACCESS_DENIED:
                    result = "Valid";
                    break;
                case (int)Status.ACCOUNT_LOCKED_OUT:
                    result = "Account locked out.";
                    break;
                case (int)Status.ACCOUNT_EXPIRED:
                    result = "Account expired.";
                    break;
                case (int)Status.INVALID_PASSWORD:
                    result = "Invalid Password";
                    break;
                case (int)Status.INVALID_CREDS:
                    result = "Invalid Creds";
                    break;
                case (int)Status.BAD_NETWORK_NAME:
                    result = "Bad Network Name";
                    break;
                case (int)Status.NO_LOGON_SERVERS:
                    result = "No logon servers available.";
                    break;
                case (int)Status.DUPLICATE_CONNECTION:
                    result = "Duplicate Connection";
                    break;
                case (int)Status.RPC_UNAVAILABLE:
                    result = "RPC Server Unavailable (may not be Windows)";
                    break;
                default:
                    result = "Other: " + conn;
                    break;
            }

            bool wasvalid = (result.Equals("Valid") || result.Equals("LOCAL ADMIN!"));
            if ((!valid && !invalid) || (valid && wasvalid) || (invalid && !wasvalid))
            {
                string final;
                if (getusers || getos)
                    final = String.Format("{0,-20}{1,-25}{2,-20}{3,-20}{4,-20}", cname, uname, pword, result, info);
                else
                    final = String.Format("{0,-20}{1,-25}{2,-20}{3,-20}", cname, uname, pword, result);
                lock (writeLockObj)
                {
                    if (result.Equals("LOCAL ADMIN!"))
                        Console.ForegroundColor = ConsoleColor.Green;
                    else if (result.Equals("Valid"))
                        Console.ForegroundColor = ConsoleColor.White;
                    else if (info.Contains("warning"))
                        Console.ForegroundColor = ConsoleColor.Yellow;
                    else
                        Console.ForegroundColor = ConsoleColor.Red;

                    Console.WriteLine(final);
                    if (output != null)
                    {
                        File.AppendAllText(output, final + Environment.NewLine);
                    }
                }
            }

            Interlocked.Decrement(ref workingCounter);
            Interlocked.Increment(ref processedCounter);
            return;

        }

        static public string GetOS(string target)
        {
            try
            {
                string[] version = FileVersionInfo.GetVersionInfo(target + "\\Windows\\System32\\ntoskrnl.exe").ProductVersion.Split('.');
                if (version.Length < 2)
                {
                    return "Unknown version: " + version[0];
                }
                switch (version[0] + "." + version[1])
                {
                    case "4":
                        return "NT 4.x";
                    case "5.0":
                        return "Windows 2000";
                    case "5.1":
                        return "Windows XP";
                    case "5.2":
                        return "Windows XP 64bit / Server 2003";
                    case "6.0":
                        return "Windows Vista / Server 2008";
                    case "6.1":
                        return "Windows 7 / Server 2008 R2";
                    case "6.2":
                        return "Windows 8 / Server 2012";
                    case "6.3":
                        return "Windows 8.1 / Server 2012 R2";
                    case "10.0":
                        return "Windows 10 / Server 2016";
                    default:
                        return "Version " + version[0] + "." + version[1] + " not identified.";
                }
            }
            catch
            {
                return "Could not get OS";
            }
        }

        static public ArrayList GetUsers(string target, double range)
        {
            ArrayList users = new ArrayList();
            string[] dirs;
            try
            {
                dirs = Directory.GetDirectories(target + "\\Users");
            }
            catch
            {
                try
                {
                    dirs = Directory.GetDirectories(target + "\\Documents and Settings");
                }
                catch
                {
                    users.Add("Unable to find Users folders");
                    return users;
                }
            }
            string[] ignore_users = { "All Users", "Default", "Default User", "Public" };
            DateTime window = DateTime.Today.AddDays(0 - range);

            string[] split;
            string username;
            DateTime now = DateTime.Now;

            foreach (string d in dirs)
            {
                //Ignore default user directories
                split = d.Split('\\');
                username = split[split.Length - 1];
                if (Array.IndexOf(ignore_users, username) != -1)
                    continue;

                //Get Modified date
                DateTime last_mod = DateTime.MinValue;
                try
                {
                    last_mod = Directory.GetLastWriteTime(d + "\\NTUSER.DAT");
                    //Save username if in range
                    if (last_mod > window)
                        users.Add(username + " (" + (now - last_mod).Days + ")");
                }
                catch
                {
                    // If NTUSER.DAT doesnt exist, try getting the directory in general
                    try
                    {
                        last_mod = Directory.GetLastWriteTime(d);
                        if (last_mod > window)
                            users.Add(username + " (~" + (now - last_mod).Days + ")");
                    }
                    catch
                    {
                        // The directory doesnt exist???  Weirdddd but ok
                        users.Add(username + " (?)");
                    }
                }
            }

            if (users.Capacity == 0)
            {
                users.Add("None within " + range + " days");
            }
            return users;
        }

        static void Main(string[] args)
        {
            string info = @"

   .d8888b.                       888 888b    888 d8b           d8b          
  d88P  Y88b                      888 8888b   888 Y8P           Y8P          
  888    888                      888 88888b  888                            
  888        888d888 .d88b.   .d88888 888Y88b 888 888 88888b.  8888  8888b.  
  888        888P""  d8P Y8b d88"" 888 888 Y88b888 888 888 ""88b ""888     ""88b
  888    888 888    88888888 888  888 888  Y88888 888 888  888  888.d888888
  Y88b  d88P 888    Y8b.Y88b 888 888   Y8888 888 888  888  888 888  888
   ""Y8888P""  888     ""Y8888   ""Y88888 888    Y888 888 888  888  888 ""Y888888 
                                                                888
                                                               d88P
                                                             888P""
                    Chris King(@raikiasec)

                  For help: CredNinja.exe -h

This script is designed to identify if credentials are valid, invalid, 
or local admin valid credentials within a domain network and will also check 
for local admin. It works by attempting to mount C$ on each server using 
different credentials.

    Author: Chris King (@raikiasec)
    Massive Contributor: Alyssa Rahman (@ramen0x3f)

Example:
	> CredNinja.exe --creds test\raikia:hunter2,test\user:password --hosts 10.10.10.10,10.20.20.20,10.30.30.30 --users --os 

Links: 
    https://github.com/Raikia/CredNinja
    https://twitter.com/raikiasec
    https://twitter.com/ramen0x3f";

            //Print help
            if (args.Length==0)
            {
                Console.WriteLine(info);
                return;
            }
            Options opt;
            //Parse out args 
            try
            {
                opt = CliParser.Parse<Options>(args);
            }
            catch (clipr.Core.ParserExit e)
            {
                return;
            }
            catch (ParseException e)
            {
                Console.WriteLine(info);
                Console.WriteLine(e.Message);
                return;
            }

            //Convert hosts and creds to arrays 
            string[] hosts = opt.hosts.Split(',');
            string[] creds = opt.creds.Split(',');

            //Reduce Hosts list to only live hosts if told to scan
            if (opt.scan)
            {
                List<string> alive_hosts = new List<string>(); //Because it's bad practice modifying an array midloop
                System.Net.Sockets.TcpClient tcp = new System.Net.Sockets.TcpClient();
                tcp.SendTimeout = opt.scan_timeout * 1000;
                tcp.ReceiveTimeout = opt.scan_timeout * 1000;

                foreach (var h in hosts)
                {
                    var result = tcp.BeginConnect(h, 445, null, null);
                    //Wait for a connection
                    var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(opt.scan_timeout));

                    //Add if successful
                    if (success)
                    {
                        alive_hosts.Add(h);
                    }
                    tcp.EndConnect(result);
                }

                hosts = alive_hosts.ToArray();
            }

            //Do the thing 
            try
            {
                Exec(hosts, creds, opt.delim, opt.users, opt.users_time, opt.valid, opt.invalid, opt.os, opt.output, opt.threads, opt.delay);
            }
            catch (Exception e)
            {
                Console.WriteLine("An error occurred: '{0}'", e);
            }
        }
    }
}
