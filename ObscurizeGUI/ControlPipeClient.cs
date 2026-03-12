using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;

namespace Obscurize
{
    /// <summary>
    /// Thin client wrapper around the Obscurize control named pipe.
    ///
    /// Protocol (matches ControlPipeListener.c in ObscurizeService):
    ///   →  4 bytes : DWORD control code
    ///   ←  4 bytes : DWORD status reply  (OBS_CTRL_QUERY_STATUS only)
    ///
    /// Every call opens a fresh connection, sends the code, reads the
    /// optional reply, and closes.  Connections time out after 2 s.
    /// </summary>
    internal static class ControlPipeClient
    {
        private const int ConnectTimeoutMs = 2000;

        // ── Fire-and-forget send ──────────────────────────────────

        /// <summary>
        /// Sends <paramref name="controlCode"/> to the service.
        /// Returns true on success; false if the service pipe is unavailable.
        /// </summary>
        internal static bool Send(int controlCode)
        {
            try
            {
                using NamedPipeClientStream pipe = OpenPipe();
                if (!TryConnect(pipe)) return false;

                using BinaryWriter writer = new(pipe, System.Text.Encoding.UTF8, leaveOpen: true);
                writer.Write(controlCode);
                return true;
            }
            catch
            {
                return false;
            }
        }

        // ── Status query ──────────────────────────────────────────

        /// <summary>
        /// Queries the service status.
        /// Returns the status code or -1 if the service is offline.
        /// </summary>
        internal static int QueryStatus()
        {
            try
            {
                using NamedPipeClientStream pipe = OpenPipe();
                if (!TryConnect(pipe)) return -1;

                // Send the query code.
                using BinaryWriter writer = new(pipe, System.Text.Encoding.UTF8, leaveOpen: true);
                writer.Write(ObscurizeConst.CtrlQueryStatus);
                writer.Flush();

                // Read the 4-byte reply.
                using BinaryReader reader = new(pipe, System.Text.Encoding.UTF8, leaveOpen: true);
                return reader.ReadInt32();
            }
            catch
            {
                return -1;
            }
        }

        // ── Service installation helpers ──────────────────────────

        /// <summary>Returns true if the service pipe is currently accepting connections.</summary>
        internal static bool IsServiceAvailable()
        {
            try
            {
                using NamedPipeClientStream pipe = OpenPipe();
                return TryConnect(pipe);
            }
            catch
            {
                return false;
            }
        }

        // ── Private helpers ───────────────────────────────────────

        private static NamedPipeClientStream OpenPipe()
            => new(
                ".",                              // local machine
                PipeNameWithoutPrefix(),
                PipeDirection.InOut,
                PipeOptions.None,
                TokenImpersonationLevel.Anonymous);

        private static bool TryConnect(NamedPipeClientStream pipe)
        {
            try
            {
                pipe.Connect(ConnectTimeoutMs);
                // Server (r77 CreatePublicNamedPipe) uses PIPE_TYPE_BYTE – must match.
                pipe.ReadMode = PipeTransmissionMode.Byte;
                return true;
            }
            catch (TimeoutException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }

        // ObscurizeConst.ControlPipeName is "\\.\pipe\ObscurizeCtrl".
        // NamedPipeClientStream wants just the pipe name without the prefix.
        private static string PipeNameWithoutPrefix()
        {
            const string prefix = @"\\.\pipe\";
            string full = ObscurizeConst.ControlPipeName;
            return full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                ? full.Substring(prefix.Length)
                : full;
        }
    }
}
