<?php

declare(strict_types=1);

namespace DFIRCopilot\Executors;

use DFIRCopilot\Config;

/**
 * Resolves file paths between host and REMnux via shared folders.
 *
 * When a virtiofs or 9p shared mount is configured, large files (disk images,
 * memory dumps) can be accessed directly by both host and VM without SFTP
 * transfer. This is critical for artifacts over ~1 GB where SFTP would take
 * minutes.
 *
 * Setup (KVM/libvirt):
 *   1. Add a filesystem passthrough in virt-manager:
 *      Source: /home/you/dfir-copilot/cases  (host path)
 *      Target: dfir-share                     (mount tag)
 *      Mode: mapped or passthrough
 *   2. On REMnux, mount it:
 *      sudo mount -t 9p -o trans=virtio dfir-share /mnt/shared
 *   3. Set config.json:
 *      "remnux.shared_host_path": "/home/you/dfir-copilot/cases"
 *      "remnux.shared_vm_path": "/mnt/shared"
 */
final class SharedPath
{
    /**
     * Check whether a host-side file can be accessed via the shared folder
     * on a remote VM, and if so, return the VM-side path.
     *
     * @param string $hostPath    Absolute path on the host
     * @param string $sharedHost  Host-side shared folder root (from config)
     * @param string $sharedVM    VM-side mount point (from config)
     * @return string|null        VM-side path if accessible, null if not
     */
    public static function resolveForVM(
        string $hostPath,
        string $sharedHost,
        string $sharedVM,
        ): ?string
    {
        if ($sharedHost === '' || $sharedVM === '') {
            return null;
        }

        // Normalise paths
        $hostPath = realpath($hostPath) ?: $hostPath;
        $sharedHost = rtrim($sharedHost, '/');
        $sharedVM = rtrim($sharedVM, '/');

        // Check if the file is under the shared folder
        if (!str_starts_with($hostPath, $sharedHost . '/') && $hostPath !== $sharedHost) {
            return null;
        }

        // Compute relative path and map to VM
        $relative = substr($hostPath, strlen($sharedHost));
        return $sharedVM . $relative;
    }

    /**
     * Decide whether to use shared folder or SFTP for a given file.
     *
     * Returns the VM-side path if shared access is available,
     * otherwise null (caller should fall back to SFTP copy).
     *
     * @param string $hostPath  Absolute path on host
     * @param Config $config    Configuration (has shared paths)
     * @return string|null      VM-side path or null
     */
    public static function resolveForREMnux(string $hostPath, Config $config): ?string
    {
        return self::resolveForVM(
            $hostPath,
            $config->remnuxSharedHostPath,
            $config->remnuxSharedVMPath,
        );
    }

    /**
     * Transfer a file to REMnux: use shared folder if available, SFTP otherwise.
     *
     * Returns the remote path where the file is accessible on REMnux.
     *
     * @param string      $hostPath   Local file path
     * @param Config      $config     Configuration
     * @param SSHExecutor $ssh        SSH connection (for SFTP fallback)
     * @param string      $remoteDir  Remote work directory (for SFTP fallback)
     * @return array{path: string, method: string}  Remote path + transfer method used
     */
    public static function ensureOnREMnux(
        string $hostPath,
        Config $config,
        SSHExecutor $ssh,
        string $remoteDir,
        ): array
    {
        // Try shared folder first
        $sharedPath = self::resolveForREMnux($hostPath, $config);
        if ($sharedPath !== null) {
            return ['path' => $sharedPath, 'method' => 'shared'];
        }

        // Fall back to SFTP
        $remotePath = $remoteDir . '/' . basename($hostPath);
        $ssh->run("mkdir -p {$remoteDir}");
        $ok = $ssh->copyTo($hostPath, $remotePath);
        if (!$ok) {
            throw new \RuntimeException("SFTP transfer failed: {$hostPath} → {$remotePath}");
        }

        return ['path' => $remotePath, 'method' => 'sftp'];
    }
}