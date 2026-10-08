using System;
using System.IO;
using System.Security;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;

internal sealed class LocalServiceAclProbe : ServiceBase
{
    private readonly string[] arguments;

    private LocalServiceAclProbe(string[] arguments)
    {
        this.arguments = arguments;
        ServiceName = arguments[0];
    }

    private static void RequireDenied(Action action)
    {
        try
        {
            action();
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }
        catch (SecurityException)
        {
            return;
        }
        throw new InvalidOperationException("Shared LocalService ACL probe unexpectedly succeeded.");
    }

    private void Report(string result)
    {
        string temporary = arguments[2] + ".tmp";
        File.WriteAllText(temporary, result);
        File.Move(temporary, arguments[2]);
    }

    protected override void OnStart(string[] args)
    {
        ThreadPool.QueueUserWorkItem(delegate
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    var principal = new WindowsPrincipal(identity);
                    if (identity.User.Value != "S-1-5-19" ||
                        principal.IsInRole(WindowsBuiltInRole.Administrator) ||
                        principal.IsInRole(new SecurityIdentifier(arguments[1])))
                    {
                        throw new InvalidOperationException("Probe is not plain LocalService without the agent service SID.");
                    }
                }
                for (int index = 3; index < 6; index++)
                {
                    string path = arguments[index];
                    RequireDenied(delegate { File.ReadAllBytes(path); });
                }
                for (int index = 6; index < 8; index++)
                {
                    string path = arguments[index];
                    RequireDenied(delegate { Directory.GetFileSystemEntries(path); });
                }
                for (int index = 8; index < 10; index++)
                {
                    string path = arguments[index];
                    RequireDenied(delegate { File.WriteAllText(path, "unauthorized"); });
                }
                Report("PASS");
            }
            catch (Exception error)
            {
                Report("FAIL: " + error);
            }
            finally
            {
                Stop();
            }
        });
    }

    private static void Main(string[] args)
    {
        if (args.Length != 10)
        {
            throw new ArgumentException("Expected service name, agent SID, result path, three files, two directories and two writes.");
        }
        ServiceBase.Run(new LocalServiceAclProbe(args));
    }
}
