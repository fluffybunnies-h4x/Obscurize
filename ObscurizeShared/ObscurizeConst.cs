// ============================================================
//  ObscurizeConst.cs  –  C# mirror of ObscurizeDef.h
//  Used by ObscurizeGUI and ObscurizeService (managed code)
// ============================================================

namespace Obscurize
{
    internal static class ObscurizeConst
    {
        // --------------------------------------------------------
        //  Operating modes
        // --------------------------------------------------------
        public const int ModeDefensive = 1;
        public const int ModeTrap      = 2;

        // --------------------------------------------------------
        //  Registry – configuration store
        //  HKEY_LOCAL_MACHINE\SOFTWARE\ObscurizeConfig
        // --------------------------------------------------------
        public const string ConfigKey          = @"SOFTWARE\ObscurizeConfig";
        public const string ConfigValueEnabled  = "Enabled";
        public const string ConfigValueMode     = "Mode";
        public const string ConfigValueUsername = "SpoofUsername";
        public const string ConfigValueCompName = "SpoofCompName";
        public const string ConfigValueMacOUI          = "SpoofMacOUI";
        public const string ConfigValueDomainEnabled   = "DomainEnabled";
        public const string ConfigValueDomainName      = "SpoofDomainName";

        // --------------------------------------------------------
        //  Registry – VM artefact keys (Defensive creates / Trap removes)
        // --------------------------------------------------------
        public const string RegVmwareRoot  = @"SOFTWARE\VMware, Inc.";
        public const string RegVmwareTools = @"SOFTWARE\VMware, Inc.\VMware Tools";
        public const string RegVboxRoot    = @"SOFTWARE\Oracle";
        public const string RegVboxGA      = @"SOFTWARE\Oracle\VirtualBox Guest Additions";
        public const string RegBiosKey     = @"HARDWARE\DESCRIPTION\System\BIOS";

        // --------------------------------------------------------
        //  Spoof values – Defensive mode
        // --------------------------------------------------------
        public const string DefManufacturer  = "VMware, Inc.";
        public const string DefProduct       = "VMware Virtual Platform";
        public const string DefBiosVendor    = "Phoenix Technologies LTD";
        public const string DefBiosVersion   = "6.00";
        public const string DefBiosDate      = "07/02/2015";
        public const string DefUsername      = "admin";
        public const string DefComputerName  = "DESKTOP-ANALY5T";
        public const int    DefScreenWidth   = 800;
        public const int    DefScreenHeight  = 600;
        public const long   DefMemoryMB      = 2048L;
        public static readonly byte[] DefMacOUI = { 0x00, 0x0C, 0x29 };

        // --------------------------------------------------------
        //  Spoof values – Trap mode defaults
        // --------------------------------------------------------
        public const string TrapManufacturer       = "Dell Inc.";
        public const string TrapProduct            = "Precision 5560";
        public const string TrapBiosVendor         = "Dell Inc.";
        public const string TrapBiosVersion        = "1.22.0";
        public const string TrapBiosDate           = "04/14/2023";
        public const string TrapUsernameDefault    = "jsmith";
        public const string TrapCompNameDefault    = "DESKTOP-J8K3M2";
        public const int    TrapScreenWidth        = 1920;
        public const int    TrapScreenHeight       = 1080;
        public const long   TrapMemoryMB           = 16384L;
        public static readonly byte[] TrapMacOUI   = { 0x00, 0x1B, 0x21 };

        // --------------------------------------------------------
        //  Domain spoof values
        // --------------------------------------------------------
        public const string SpoofDomainActive   = "CORP.DEV";
        public const string SpoofDomainInactive = "WORKGROUP";

        // --------------------------------------------------------
        //  Named pipe – GUI control interface
        // --------------------------------------------------------
        public const string ControlPipeName = @"\\.\pipe\ObscurizeCtrl";

        // --------------------------------------------------------
        //  Control codes  (GUI -> Service)
        // --------------------------------------------------------
        public const int CtrlEnable            = 0x0001;
        public const int CtrlDisable           = 0x0002;
        public const int CtrlSetModeDefensive  = 0x0003;
        public const int CtrlSetModeTrap       = 0x0004;
        public const int CtrlQueryStatus       = 0x0005;
        public const int CtrlInjectAll         = 0x0006;
        public const int CtrlDetachAll         = 0x0007;
        public const int CtrlDomainEnable      = 0x0008;
        public const int CtrlDomainDisable     = 0x0009;

        // Status reply codes  (Service -> GUI)
        public const int StatusOk              = 0x0000;
        public const int StatusDisabled        = 0x0001;
        public const int StatusModeDefensive   = 0x0002;
        public const int StatusModeTrap        = 0x0003;
        public const int StatusError           = 0xFFFF;

        // --------------------------------------------------------
        //  Agent header
        // --------------------------------------------------------
        public const int    AgentHeaderOffset    = 40;
        public const ushort AgentSignature       = 0x4253;
        public const ushort ServiceSignature     = 0x5653;

        // --------------------------------------------------------
        //  Known VM process names (displayed in GUI status panel)
        // --------------------------------------------------------
        public static readonly string[] VmProcessNames =
        {
            "vmtoolsd.exe",
            "VBoxService.exe",
            "VBoxTray.exe",
            "vmsrvc.exe",
            "vmusrvc.exe",
            "VGAuthService.exe",
            "vmwaretray.exe",
            "vmwareuser.exe",
            "vmacthlp.exe",
        };

        // --------------------------------------------------------
        //  Known VM service names
        // --------------------------------------------------------
        public static readonly string[] VmServiceNames =
        {
            "VMTools",
            "VBoxGuest",
            "VBoxMouse",
            "VBoxSF",
            "VBoxVideo",
            "VGAuthService",
            "vmhgfs",
            "vmci",
            "vmvss",
            "VBoxService",
        };
    }
}
