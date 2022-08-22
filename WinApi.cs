using System.Runtime.InteropServices;

namespace AdministratorGroup
{
    public enum ETokenInformationClass
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        MaxTokenInfoClass
    }

    public enum ETokenElevationType
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited
    }

    public enum ESecurityImpersonationLevel
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }
    internal class WinApi
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean GetTokenInformation(IntPtr tokenHandle,
                                                         ETokenInformationClass tokenInformationClass,
                                                         IntPtr tokenInformation,
                                                         UInt32 tokenInformationLength,
                                                         out UInt32 returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean DuplicateToken(IntPtr tokenHandle, ESecurityImpersonationLevel impersonationLevel, ref IntPtr duplicateTokenHandle);

    }
}
