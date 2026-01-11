use serde::Serialize;
use sysinfo::{CpuExt, DiskExt, System, SystemExt};

use anyhow::{anyhow, Result};

#[derive(Serialize)]
pub struct CpuMetrics {
    pub usage: f64,
    pub frequency: u64,
}

#[derive(Serialize)]
pub struct RamMetrics {
    pub used: u64,
    pub total: u64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct DiskMetrics {
    pub used: u64,
    pub total: u64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct Metrics {
    pub cpu: CpuMetrics,
    pub ram: RamMetrics,
    pub disk: DiskMetrics,
}

pub fn collect_metrics() -> Result<Metrics> {
    let mut sys = System::new_all();
    sys.refresh_memory();
    sys.refresh_disks_list();
    sys.refresh_disks();
    sys.refresh_cpu();
    std::thread::sleep(std::time::Duration::from_millis(250));
    sys.refresh_cpu();

    let cpu = sys.global_cpu_info();
    let cpu_usage = cpu.cpu_usage() as f64;
    let cpu_freq = cpu.frequency() as u64; // MHz

    let total_ram_mb = sys.total_memory() / 1024; // KiB -> MiB
    let used_ram_mb = sys.used_memory() / 1024; // KiB -> MiB
    let ram_percentage = if total_ram_mb > 0 {
        (used_ram_mb as f64 / total_ram_mb as f64) * 100.0
    } else {
        0.0
    };

    // Attempt to find disk mounted at C:\
    let mut used_disk_mb = 0u64;
    let mut total_disk_mb = 0u64;

    let mut fallback = None;

    for disk in sys.disks() {
        let mount = disk.mount_point().to_string_lossy();
        let total = disk.total_space();
        let used = total.saturating_sub(disk.available_space());

        if total_disk_mb == 0 {
            fallback = Some((used, total));
        }

        if mount.starts_with("C:") || mount.starts_with("c:") {
            total_disk_mb = total / 1_048_576; // bytes -> MB
            used_disk_mb = used / 1_048_576;
            break;
        }
    }

    if total_disk_mb == 0 {
        if let Some((used, total)) = fallback {
            total_disk_mb = total / 1_048_576;
            used_disk_mb = used / 1_048_576;
        }
    }

    if total_disk_mb == 0 {
        return Err(anyhow!("No disks detected"));
    }

    let disk_percentage = if total_disk_mb > 0 {
        (used_disk_mb as f64 / total_disk_mb as f64) * 100.0
    } else {
        0.0
    };

    Ok(Metrics {
        cpu: CpuMetrics {
            usage: cpu_usage,
            frequency: cpu_freq,
        },
        ram: RamMetrics {
            used: used_ram_mb,
            total: total_ram_mb,
            percentage: ram_percentage,
        },
        disk: DiskMetrics {
            used: used_disk_mb,
            total: total_disk_mb,
            percentage: disk_percentage,
        },
    })
}
