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
        //  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DeviceCache
        //
        //  Stored under an innocuous Windows-style path; value names blend
        //  with legitimate device-management entries.
        // --------------------------------------------------------
        public const string ConfigKey                = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\DeviceCache";
        public const string ConfigValueEnabled       = "DeviceState";
        public const string ConfigValueMode          = "CacheLevel";
        public const string ConfigValueUsername      = "UserSID";
        public const string ConfigValueCompName      = "HostBinding";
        public const string ConfigValueMacOUI        = "HardwarePrefix";
        public const string ConfigValueDomainMode    = "NetworkScope";
        public const string ConfigValueDomainName    = "NetworkDomain";

        // --------------------------------------------------------
        //  Domain mode constants
        // --------------------------------------------------------
        public const int DomainModeOff       = 0;   // Hook disabled; real domain info returned
        public const int DomainModeWorkgroup = 1;   // Force WORKGROUP / PartOfDomain: False
        public const int DomainModeJoined    = 2;   // Force domain-joined / PartOfDomain: True

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
        public const string DefUsername      = "sandbox name + suffix";   // e.g. admin4Kj9Pq – random per-process
        public const string DefComputerName  = "DESKTOP-XXXXXXX";          // 7-char random suffix – random per-process
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
        public const string TrapUsernameDefault    = "firstname.lastname";   // e.g. james.miller – random per-process
        public const string TrapCompNameDefault    = "XXX-XXXXXX";           // e.g. BKR-F3M7KP – random per-process
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
        public const int CtrlDomainOff         = 0x0008;
        public const int CtrlDomainWorkgroup   = 0x0009;
        public const int CtrlDomainJoined      = 0x000B;

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
