using AdministratorGroup;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;


var identity = WindowsIdentity.GetCurrent();
WindowsPrincipal winPrincipal = new WindowsPrincipal(identity);
Console.WriteLine($"[NET] Current principal is in role {winPrincipal.IsInRole(WindowsBuiltInRole.Administrator)}");
Console.WriteLine($"[Native] Current principal is in role {IsInAdministatorsGroup(identity)}");

Console.ReadKey();

static Boolean IsInAdministatorsGroup(WindowsIdentity userIdentity)
{
    IntPtr tokenInformation = IntPtr.Zero;
    IntPtr linkedToken = IntPtr.Zero;
    ETokenElevationType tokenElevationType = default;

    try
    {
        IntPtr tokenHandle = userIdentity.Token;
        Int32 tokenInformationLength = Marshal.SizeOf(typeof(Int32));
        tokenInformation = Marshal.AllocHGlobal(tokenInformationLength);

        Boolean isSuccess;
        try
        {
            isSuccess = WinApi.GetTokenInformation(tokenHandle,
                ETokenInformationClass.TokenElevationType,
                tokenInformation,
                (UInt32)tokenInformationLength,
                out UInt32 _);
        }
        catch (Exception e)
        {
            throw;
        }

        if (!isSuccess)
        {
            throw new Win32Exception("Failed to get token information.");
        }

        Int32 tokenInformationValue = Marshal.ReadInt32(tokenInformation);
        tokenElevationType = (ETokenElevationType)tokenInformationValue;

        if (tokenElevationType == ETokenElevationType.TokenElevationTypeLimited)
        {
            int bufferSize = IntPtr.Size;
            uint retSize = 0;
            linkedToken = Marshal.AllocHGlobal(bufferSize);
            if (linkedToken == IntPtr.Zero)
            {
                throw new Exception("Invalid token");
            }

            if (!WinApi.GetTokenInformation(tokenHandle,
                ETokenInformationClass.TokenLinkedToken, linkedToken,
                (UInt32)bufferSize, out retSize))
            {
                throw new Win32Exception("Failed to get linked token.");
            }
            // If this value is larger than the value specified in the TokenInformationLength parameter
            // the function fails and stores no data in the buffer.
            IntPtr lt = Marshal.ReadIntPtr(linkedToken);
            if (retSize > bufferSize)
            {
                if (!WinApi.DuplicateToken(tokenHandle,
                        ESecurityImpersonationLevel.SecurityImpersonation,
                        ref lt))
                {
                    throw new Win32Exception("Failed to duplicate token.");
                }
            }


            WindowsIdentity id = new WindowsIdentity(lt);
            WindowsPrincipal principal = new WindowsPrincipal(id);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        return tokenElevationType == ETokenElevationType.TokenElevationTypeFull;
    }
    finally
    {
        if (tokenInformation != IntPtr.Zero)
            Marshal.FreeHGlobal(tokenInformation);
        if (linkedToken != IntPtr.Zero)
            Marshal.FreeHGlobal(linkedToken);
    }
}


