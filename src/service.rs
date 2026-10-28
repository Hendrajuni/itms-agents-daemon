use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

pub const SERVICE_NAME: &str = "ITMSAgentService";
pub const SERVICE_DISPLAY_NAME: &str = "ITMS Endpoint Telemetry Daemon";
pub const SERVICE_DESCRIPTION: &str = "ITMS Windows Endpoint Agent for Application and DNS Telemetry Tracking";

define_windows_service!(ffi_service_main, my_service_main);

pub fn run_as_service() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn my_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Error saat menjalankan service {}: {:?}", SERVICE_NAME, e);
    }
}

fn run_service(_arguments: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_handler = stop_signal.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                info!("Menerima sinyal Stop/Shutdown dari Windows Service Manager.");
                stop_signal_handler.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Laporkan status RUNNING ke SCM
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Jalankan Tokio runtime untuk memproses daemon
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        crate::run_daemon_loops(stop_signal).await;
    });

    // Laporkan status STOPPED ke SCM
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

/// Helper instalasi service ke SCM menggunakan sc.exe bawaan Windows
pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = std::env::current_exe()?;
    let exe_str = exe_path.to_string_lossy();

    info!("Mendaftarkan service {}...", SERVICE_NAME);
    let cmd_str = format!(
        "sc create {} binPath= \"\\\"{}\\\" service\" DisplayName= \"{}\" start= auto",
        SERVICE_NAME, exe_str, SERVICE_DISPLAY_NAME
    );

    let output = std::process::Command::new("cmd.exe")
        .args(["/c", &cmd_str])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);

    if !output.status.success() || stdout.contains("FAILED") || stdout.contains("ERROR") {
        return Err(format!("Gagal mendaftarkan service ke Windows SCM: {}", stdout).into());
    }

    // Atur deskripsi service
    let desc_cmd = format!("sc description {} \"{}\"", SERVICE_NAME, SERVICE_DESCRIPTION);
    let _ = std::process::Command::new("cmd.exe")
        .args(["/c", &desc_cmd])
        .output();

    Ok(())
}

/// Helper uninstalasi service dari SCM
pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    info!("Menghapus service {}...", SERVICE_NAME);
    let output = std::process::Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .output()?;

    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

/// Helper memulai service via sc.exe
pub fn start_service() -> Result<(), Box<dyn std::error::Error>> {
    info!("Memulai service {}...", SERVICE_NAME);
    let output = std::process::Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .output()?;

    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

/// Helper menghentikan service via sc.exe
pub fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    info!("Menghentikan service {}...", SERVICE_NAME);
    let output = std::process::Command::new("sc.exe")
        .args(["stop", SERVICE_NAME])
        .output()?;

    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}
