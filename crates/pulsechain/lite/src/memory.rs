//! The memory the node may use, and the budgets sized from it.
//!
//! The memory found is the process's cgroup memory limit when one is set and below physical RAM,
//! else physical RAM. On cgroup v2 the limit is the lower of `memory.max` and `memory.high`. The
//! default `--cache.size` and the held-body budget are shares of it, and the default `--cache.size`
//! is cut to what the fixed budgets leave (`config::memory_budgets`).

use crate::chain::MAX_BODY_BYTES;

const MIB: u64 = 1 << 20;

/// The default `--cache.size` as a share of the memory found, in percent.
pub const CACHE_PERCENT: u64 = 25;
/// The smallest default `--cache.size` on a box where it fits beside the fixed budgets.
pub const MIN_CACHE_BYTES: u64 = 64 * MIB;
/// The largest default `--cache.size`, and the default when memory cannot be read.
pub const MAX_CACHE_BYTES: u64 = 1 << 30;
/// The held-body budget as a share of the memory found, in percent.
pub const BODY_PERCENT: u64 = 10;
/// The smallest held-body budget. The largest, and the budget when memory cannot be read, is
/// [`MAX_BODY_BYTES`].
pub const MIN_BODY_BYTES: u64 = 32 * MIB;
/// Memory kept for the runtime, the network and the EVM, outside every budget.
pub const RUNTIME_BYTES: u64 = 256 * MIB;
/// A cgroup limit at or above this is no limit: cgroup v1 writes about 2^63 for none.
#[cfg(any(target_os = "linux", test))]
const NO_LIMIT: u64 = 1 << 60;

/// Where the memory found comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySource {
    /// The process's cgroup memory limit.
    Cgroup,
    /// Physical RAM.
    Ram,
}

impl std::fmt::Display for MemorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cgroup => "cgroup memory limit",
            Self::Ram => "physical RAM",
        })
    }
}

/// The memory the process may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memory {
    /// Bytes.
    pub bytes: u64,
    /// Where `bytes` comes from.
    pub source: MemorySource,
}

impl Memory {
    /// The default `--cache.size`: [`CACHE_PERCENT`] of the memory, within [`MIN_CACHE_BYTES`]
    /// and [`MAX_CACHE_BYTES`].
    pub fn default_cache(&self) -> u64 {
        (self.bytes / 100 * CACHE_PERCENT).clamp(MIN_CACHE_BYTES, MAX_CACHE_BYTES)
    }

    /// The held-body budget: [`BODY_PERCENT`] of the memory, within [`MIN_BODY_BYTES`] and
    /// [`MAX_BODY_BYTES`].
    pub fn body_budget(&self) -> u64 {
        (self.bytes / 100 * BODY_PERCENT).clamp(MIN_BODY_BYTES, MAX_BODY_BYTES)
    }
}

/// The memory the process may use, or `None` when neither a cgroup limit nor physical RAM can be
/// read.
pub fn detect() -> Option<Memory> {
    choose(cgroup_limit(), physical_ram())
}

/// The cgroup limit when it is below `ram` (or `ram` is unknown), else `ram`.
const fn choose(cgroup: Option<u64>, ram: Option<u64>) -> Option<Memory> {
    match (cgroup, ram) {
        (Some(c), Some(r)) if c < r => Some(Memory { bytes: c, source: MemorySource::Cgroup }),
        (_, Some(r)) => Some(Memory { bytes: r, source: MemorySource::Ram }),
        (Some(c), None) => Some(Memory { bytes: c, source: MemorySource::Cgroup }),
        (None, None) => None,
    }
}

fn physical_ram() -> Option<u64> {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory_specifics(sysinfo::MemoryRefreshKind::nothing().with_ram());
    Some(sys.total_memory()).filter(|b| *b > 0)
}

#[cfg(target_os = "linux")]
fn cgroup_limit() -> Option<u64> {
    let cgroups = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    cgroup_limit_in(&cgroups, std::path::Path::new("/sys/fs/cgroup"))
}

#[cfg(not(target_os = "linux"))]
const fn cgroup_limit() -> Option<u64> {
    None
}

/// The tightest memory limit on the process's cgroup and its ancestors, read under `root` (the
/// cgroup mount). `cgroups` is the text of `/proc/self/cgroup`. A systemd unit's `MemoryMax=`
/// sits on the unit's own cgroup, not at `root`, so the path from `cgroups` is walked up.
/// cgroup v2 reads `memory.max` and `memory.high` (`MemoryHigh=`, past which the kernel
/// throttles the process), v1 `memory/<path>/memory.limit_in_bytes`.
#[cfg(any(target_os = "linux", test))]
fn cgroup_limit_in(cgroups: &str, root: &std::path::Path) -> Option<u64> {
    let mut tightest: Option<u64> = None;
    for line in cgroups.lines() {
        let mut parts = line.splitn(3, ':');
        let (Some(_), Some(controllers), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue
        };
        let (base, files): (_, &[&str]) = if controllers.is_empty() {
            (root.to_path_buf(), &["memory.max", "memory.high"])
        } else if controllers.split(',').any(|c| c == "memory") {
            (root.join("memory"), &["memory.limit_in_bytes"])
        } else {
            continue
        };
        for dir in std::path::Path::new(path.trim_start_matches('/')).ancestors() {
            for file in files {
                let Ok(text) = std::fs::read_to_string(base.join(dir).join(file)) else { continue };
                if let Some(limit) = parse_limit(&text) {
                    tightest = Some(tightest.map_or(limit, |t| t.min(limit)));
                }
            }
        }
    }
    tightest
}

/// A cgroup limit file's value, or `None` for `max`, a value at or above [`NO_LIMIT`] or text
/// that is not a number.
#[cfg(any(target_os = "linux", test))]
fn parse_limit(text: &str) -> Option<u64> {
    text.trim().parse::<u64>().ok().filter(|b| *b < NO_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const GIB: u64 = 1 << 30;

    #[test]
    fn a_limit_file_reads_max_and_huge_values_as_no_limit() {
        assert_eq!(parse_limit("536870912\n"), Some(512 * MIB));
        assert_eq!(parse_limit("max\n"), None);
        // cgroup v1 with no limit.
        assert_eq!(parse_limit("9223372036854771712\n"), None);
        assert_eq!(parse_limit(""), None);
        assert_eq!(parse_limit("12k"), None);
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn cgroup_v2_takes_the_tightest_limit_on_the_unit_and_its_slices() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let cgroups = "0::/system.slice/reth-lite.service\n";
        assert_eq!(cgroup_limit_in(cgroups, root), None);
        write(root, "memory.max", "max\n");
        write(root, "system.slice/memory.max", "max\n");
        write(root, "system.slice/reth-lite.service/memory.max", "1073741824\n");
        assert_eq!(cgroup_limit_in(cgroups, root), Some(GIB));
        write(root, "system.slice/memory.max", "536870912\n");
        assert_eq!(cgroup_limit_in(cgroups, root), Some(512 * MIB));
        // In a cgroup namespace the process sits at the root.
        write(root, "memory.max", "268435456\n");
        assert_eq!(cgroup_limit_in("0::/\n", root), Some(256 * MIB));
    }

    /// systemd's `MemoryHigh=` is `memory.high`: past it the kernel throttles the process.
    #[test]
    fn cgroup_v2_counts_memory_high_beside_memory_max() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let cgroups = "0::/system.slice/reth-lite.service\n";
        write(root, "system.slice/reth-lite.service/memory.high", "1073741824\n");
        assert_eq!(cgroup_limit_in(cgroups, root), Some(GIB));
        write(root, "system.slice/reth-lite.service/memory.max", "2147483648\n");
        assert_eq!(cgroup_limit_in(cgroups, root), Some(GIB));
        write(root, "system.slice/memory.max", "536870912\n");
        assert_eq!(cgroup_limit_in(cgroups, root), Some(512 * MIB));
        write(root, "system.slice/memory.high", "268435456\n");
        assert_eq!(cgroup_limit_in(cgroups, root), Some(256 * MIB));
        write(root, "system.slice/memory.high", "max\n");
        write(root, "system.slice/reth-lite.service/memory.high", "max\n");
        assert_eq!(cgroup_limit_in(cgroups, root), Some(512 * MIB));
    }

    #[test]
    fn cgroup_v1_reads_the_memory_controller_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "memory/docker/abc/memory.limit_in_bytes", "805306368\n");
        write(root, "cpu/docker/abc/memory.limit_in_bytes", "1\n");
        let cgroups = "5:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n";
        assert_eq!(cgroup_limit_in(cgroups, root), Some(768 * MIB));
        assert_eq!(cgroup_limit_in("5:cpu,cpuacct:/docker/abc\n", root), None);
        // No limit set: v1 shows about 2^63.
        write(root, "memory/docker/abc/memory.limit_in_bytes", "9223372036854771712\n");
        assert_eq!(cgroup_limit_in(cgroups, root), None);
    }

    #[test]
    fn a_cgroup_limit_counts_only_below_physical_ram() {
        let cgroup = |bytes| Some(Memory { bytes, source: MemorySource::Cgroup });
        let ram = |bytes| Some(Memory { bytes, source: MemorySource::Ram });
        assert_eq!(choose(Some(GIB), Some(16 * GIB)), cgroup(GIB));
        assert_eq!(choose(Some(32 * GIB), Some(16 * GIB)), ram(16 * GIB));
        assert_eq!(choose(None, Some(16 * GIB)), ram(16 * GIB));
        assert_eq!(choose(Some(GIB), None), cgroup(GIB));
        assert_eq!(choose(None, None), None);
    }

    #[test]
    fn this_host_has_memory() {
        let found = detect().expect("memory is readable here");
        assert!(found.bytes >= 64 * MIB, "{found:?}");
    }

    #[test]
    fn budgets_are_shares_of_memory_within_their_bounds() {
        let mem = |bytes| Memory { bytes, source: MemorySource::Ram };
        for (bytes, cache, body) in [
            (128 * MIB, MIN_CACHE_BYTES, MIN_BODY_BYTES),
            (GIB, GIB / 100 * 25, GIB / 100 * 10),
            (2 * GIB, 2 * GIB / 100 * 25, 2 * GIB / 100 * 10),
            (4 * GIB, 4 * GIB / 100 * 25, MAX_BODY_BYTES),
            (5 * GIB, MAX_CACHE_BYTES, MAX_BODY_BYTES),
            (64 * GIB, MAX_CACHE_BYTES, MAX_BODY_BYTES),
            (u64::MAX, MAX_CACHE_BYTES, MAX_BODY_BYTES),
        ] {
            assert_eq!(mem(bytes).default_cache(), cache, "{bytes}");
            assert_eq!(mem(bytes).body_budget(), body, "{bytes}");
        }
        assert_eq!((MIN_CACHE_BYTES, MAX_CACHE_BYTES), (64 * MIB, GIB));
        assert_eq!((MIN_BODY_BYTES, MAX_BODY_BYTES), (32 * MIB, 256 * MIB));
    }
}
