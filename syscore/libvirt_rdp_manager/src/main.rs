use anyhow::Result;
use clap::{Parser, Subcommand};
use console::style;
use dialoguer::{
    theme::ColorfulTheme, Confirm, FuzzySelect, Input, Password, Select
};
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Table, row};
use virt::connect::Connect;
use virt::domain::Domain;
use virt::error::Error as VirtError;
use libvirt_sys::{
    VIR_DOMAIN_RUNNING,
    VIR_DOMAIN_SHUTOFF,
    VIR_DOMAIN_PAUSED
};

// Helper function to check domain state
fn is_domain_running(state: i32) -> bool {
    state == VIR_DOMAIN_RUNNING as i32
}

fn is_domain_shutoff(state: i32) -> bool {
    state == VIR_DOMAIN_SHUTOFF as i32
}

fn is_domain_paused(state: i32) -> bool {
    state == VIR_DOMAIN_PAUSED as i32
}

fn state_to_string(state: i32) -> &'static str {
    match state as u32 {
        x if x == VIR_DOMAIN_RUNNING => "running",
        x if x == VIR_DOMAIN_SHUTOFF => "shut off",
        x if x == VIR_DOMAIN_PAUSED => "paused",
        _ => "unknown"
    }
}
use log::info;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Connect to a VM using RDP
    Connect {
        /// Name of the VM to connect to
        vm_name: String,
        /// RDP username
        #[arg(short, long)]
        username: Option<String>,
        /// RDP password
        #[arg(short, long)]
        password: Option<String>,
        /// RDP port (default: 3389)
        #[arg(short, long, default_value_t = 3389)]
        port: u16,
    },
    /// Power on a VM
    Start {
        /// Name of the VM to start
        vm_name: String,
    },
    /// Power off a VM
    Stop {
        /// Name of the VM to stop
        vm_name: String,
        /// Force stop (equivalent to power off)
        #[arg(short, long)]
        force: bool,
    },
    /// Restart a VM
    Restart {
        /// Name of the VM to restart
        vm_name: String,
        /// Force restart
        #[arg(short, long)]
        force: bool,
    },
    /// List all VMs and their status
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // If no arguments, start interactive mode
    if std::env::args().count() == 1 {
        interactive_mode().await?;
    } else {
        // CLI mode
        let cli = Cli::parse();
        match cli.command {
            Commands::Connect {
                vm_name,
                username,
                password,
                port,
            } => connect_vm(&vm_name, username, password, port),
            Commands::Start { vm_name } => start_vm(&vm_name),
            Commands::Stop { vm_name, force } => stop_vm(&vm_name, force),
            Commands::Restart { vm_name, force } => restart_vm(&vm_name, force),
            Commands::List => list_vms(),
        }?;
    }
    
    Ok(())
}

async fn interactive_mode() -> Result<()> {
    let theme = ColorfulTheme::default();
    
    loop {
        println!("\n{}", style("=== VM Manager ===").bold().blue());
        
        let selection = Select::with_theme(&theme)
            .with_prompt("Select an option")
            .default(0)
            .items(&[
                "List VMs",
                "Start VM",
                "Stop VM",
                "Restart VM",
                "Connect to VM (RDP)",
                "Exit"
            ])
            .interact()?;
        
        match selection {
            0 => list_vms_interactive()?,
            1 => start_vm_interactive()?,
            2 => stop_vm_interactive()?,
            3 => restart_vm_interactive()?,
            4 => connect_vm_interactive().await?,
            5 => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Invalid selection"),
        }
    }
    
    Ok(())
}

fn get_libvirt_connection() -> Result<Connect, VirtError> {
    let conn = Connect::open(Some("qemu:///system"))?;
    Ok(conn)
}

fn get_domain(conn: &Connect, name: &str) -> Result<Domain, VirtError> {
    let domains = conn.list_all_domains(0)?;
    for domain in domains {
        if let Ok(domain_name) = domain.get_name() {
            if domain_name == name {
                return Ok(domain);
            }
        }
    }
    // Use the last error from libvirt or create a new one
    Err(VirtError::last_error())
}

fn get_domain_state(domain: &Domain) -> Result<i32, VirtError> {
    let info = domain.get_info()?;
    Ok(info.state as i32)
}

fn connect_vm(vm_name: &str, username: Option<String>, password: Option<String>, port: u16) -> Result<()> {
    let conn = get_libvirt_connection()?;
    let domain = get_domain(&conn, vm_name)?;
    
    // Check if VM is running
    let state = get_domain_state(&domain)?;
    if !is_domain_running(state) {
        anyhow::bail!("VM '{}' is not running. Current state: {}", vm_name, state_to_string(state));
    }

    // Get VM's IP address (this is a simplified version, you might need to adjust)
    let xml = domain.get_xml_desc(0)?;
    let ip_address = extract_ip_from_xml(&xml).ok_or_else(|| 
        anyhow::anyhow!("Could not determine IP address for VM {}", vm_name)
    )?;

    // IP address is now extracted from XML

    // Build xfreerdp command (using xfreerdp3 on Arch Linux)
    let mut cmd = Command::new("xfreerdp3");
    
    // Add common parameters
    cmd.arg(format!("/v:{}", ip_address))
       .arg(format!("/port:{}", port))
    //    .arg("/dynamic-resolution")
    //    .arg("/gdi:hw")
    //    .arg("+clipboard")
       .arg("/drive:shared,/tmp")
       .arg("/auth-pkg-list:!kerberos");
    //    .arg("/sec:nla")
    //    .arg("/network:auto")
    //    .arg("/sec-rdp")
    //    .arg("/sec-tls");

    // Add credentials if provided
    if let Some(user) = username {
        cmd.arg(format!("/u:{}", user));
    }
    
    if let Some(pass) = password {
        cmd.arg(format!("/p:{}", pass));
    } else {
        cmd.arg("/cert-ignore");
    }

    info!("Connecting to VM '{}' at {}:{}", vm_name, ip_address, port);
    
    // Execute the command
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("xfreerdp3 command failed with status: {:?}", status);
    }

    Ok(())
}

fn start_vm(vm_name: &str) -> Result<()> {
    let conn = get_libvirt_connection()?;
    let domain = get_domain(&conn, vm_name)?;
    
    let state = get_domain_state(&domain)?;
    if state == VIR_DOMAIN_RUNNING as i32 {
        println!("VM '{}' is already running", vm_name);
        return Ok(());
    }
    
    domain.create()?;
    info!("Started VM '{}'", vm_name);
    Ok(())
}

fn stop_vm(vm_name: &str, force: bool) -> Result<()> {
    let conn = get_libvirt_connection()?;
    let domain = get_domain(&conn, vm_name)?;
    
    let state = get_domain_state(&domain)?;
    if state != VIR_DOMAIN_RUNNING as i32 {
        println!("VM '{}' is not running", vm_name);
        return Ok(());
    }
    
    if force {
        domain.destroy()?;
        info!("Force stopped VM '{}'", vm_name);
    } else {
        domain.shutdown()?;
        info!("Sent shutdown signal to VM '{}'", vm_name);
    }
    
    Ok(())
}

fn restart_vm(vm_name: &str, force: bool) -> Result<()> {
    stop_vm(vm_name, force)?;
    
    // Wait a bit before starting again
    thread::sleep(Duration::from_secs(5));
    
    start_vm(vm_name)
}

fn extract_ip_from_xml(xml: &str) -> Option<String> {
    use roxmltree::Document;
    
    println!("\n=== Debug: Starting IP extraction ===");
    println!("XML content (first 200 chars): {}", &xml[..200.min(xml.len())]);
    
    let doc = match Document::parse(xml) {
        Ok(doc) => doc,
        Err(e) => {
            eprintln!("Failed to parse XML: {}", e);
            return None;
        }
    };

    // First, try to find the MAC address in the XML
    let mut mac_address = None;
    for node in doc.descendants() {
        if node.tag_name().name() == "mac" {
            if let Some(addr) = node.attribute("address") {
                mac_address = Some(addr.to_string());
                println!("Found MAC address in XML: {}", addr);
                break;
            }
        }
    }

    // If we found a MAC address, try to get its IP using virsh
    if let Some(mac) = mac_address {
        println!("Trying to get IP for MAC: {}", mac);
        
        // First try with the default network (usually 'default' or 'virbr0')
        let networks = ["default", "virbr0", "bridge"];
        let mut output = None;
        
        for network in &networks {
            println!("Trying network: {}", network);
            let result = std::process::Command::new("virsh")
                .args(&["net-dhcp-leases", network, "--mac", &mac])
                .output();
                
            match result {
                Ok(out) => {
                    if out.status.success() {
                        output = Some(out);
                        break;
                    }
                    eprintln!("Failed with network {}: {}", network, String::from_utf8_lossy(&out.stderr));
                }
                Err(e) => eprintln!("Error running virsh with network {}: {}", network, e),
            }
        }
        
        let output = match output {
            Some(out) => out,
            None => return None,
        };
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        println!("virsh output: {}", output_str);
        
        if output.status.success() {
            // The output has a header line, then a separator line, then data
            let mut lines = output_str.lines().skip(2); // Skip header and separator
            if let Some(line) = lines.next() {
                println!("Processing line: {}", line);
                let parts: Vec<&str> = line.split_whitespace().collect();
                
                // The columns are: [date, time, MAC, protocol, IP, hostname, client_id]
                // We want the IP address (index 4)
                if parts.len() >= 5 {
                    let ip_with_prefix = parts[4];
                    if let Some(ip) = ip_with_prefix.split('/').next() {
                        if !ip.is_empty() && ip != "-" {
                            println!("Found IP: {}", ip);
                            return Some(ip.to_string());
                        }
                    }
                } else {
                    eprintln!("Unexpected line format: {}", line);
                }
            }
        } else {
            eprintln!("virsh command failed: {}", String::from_utf8_lossy(&output.stderr));
        }
    } else {
        eprintln!("No MAC address found in VM XML");
    }

    eprintln!("=== Debug: IP extraction failed ===");
    None
}

fn list_vms() -> Result<()> {
    let conn = get_libvirt_connection()?;
    let flags = 0; // No flags
    let domains = conn.list_all_domains(flags)?;
    
    let mut table = Table::new();
    table.add_row(row![bFg=> "Name", "State", "ID", "Autostart"]);
    
    for domain in domains {
        let name = domain.get_name()?;
        let id = domain.get_id().unwrap_or(0);
        let autostart = domain.get_autostart().unwrap_or(false);
        let state = match domain.get_info() {
            Ok(info) => {
                match info.state as i32 {
                    x if is_domain_running(x) => 
                        style("Running").green().to_string(),
                    x if is_domain_shutoff(x) => 
                        style("Stopped").red().to_string(),
                    x if is_domain_paused(x) => 
                        style("Paused").yellow().to_string(),
                    _ => format!("Unknown ({})", info.state),
                }
            },
            Err(_) => "UNKNOWN".to_string(),
        };
        
        table.add_row(row![
            name,
            state,
            if id == 0 { "-".to_string() } else { id.to_string() },
            if autostart { "Yes" } else { "No" }
        ]);
    }
    
    table.printstd();
    Ok(())
}

fn list_vms_interactive() -> Result<()> {
    println!("\n{}", style("=== List of Virtual Machines ===").bold().blue());
    list_vms()
}

fn start_vm_interactive() -> Result<()> {
    let conn = get_libvirt_connection()?;
    let domains = conn.list_all_domains(0)?;
    
    let mut choices = Vec::new();
    for domain in &domains {
        if let Ok(name) = domain.get_name() {
            if let Ok(info) = domain.get_info() {
                if !is_domain_running(info.state as i32) {
                    choices.push((name, domain.clone()));
                }
            }
        }
    }
    
    if choices.is_empty() {
        println!("\n{}", style("No stopped VMs found").yellow());
        return Ok(());
    }
    
    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select VM to start")
        .items(&choices.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>())
        .default(0)
        .interact()?;
    
    let (vm_name, domain) = &choices[selection];
    let vm_name = vm_name.clone();
    let domain = domain.clone();
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
            .template("{spinner:.green} {msg}")?,
    );
    spinner.set_message(format!("Starting VM: {}...", vm_name));
    spinner.enable_steady_tick(Duration::from_millis(100));

    // Start the VM in a separate thread
    let handle = std::thread::spawn(move || {
        match domain.create() {
            Ok(_) => {
                spinner.finish_with_message(format!("Successfully started VM: {}", vm_name));
                Ok(())
            }
            Err(e) => {
                spinner.finish_with_message(format!("Failed to start VM: {}", e));
                Err(e)
            }
        }
    });

    // Wait for the VM to start
    handle.join().map_err(|_| anyhow::anyhow!("Failed to join thread"))??;
    Ok(())
}

fn stop_vm_interactive() -> Result<()> {
    let conn = get_libvirt_connection()?;
    let domains = conn.list_all_domains(0)?;
    
    let mut choices = Vec::new();
    for domain in &domains {
        if let Ok(name) = domain.get_name() {
            if let Ok(state) = get_domain_state(domain) {
                if is_domain_running(state) {
                    choices.push((name, domain.clone()));
                }
            }
        }
    }
    
    if choices.is_empty() {
        println!("\n{}", style("No running VMs found").yellow());
        return Ok(());
    }
    
    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select VM to stop")
        .items(&choices.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>())
        .default(0)
        .interact()?;
    
    let (vm_name, domain) = &choices[selection];
    
    let force = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Force stop? (power off)")
        .default(false)
        .interact()?;
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Stopping VM: {}...", vm_name));
    
    if force {
        domain.destroy()?;
        spinner.finish_with_message(format!("Force stopped VM: {}", vm_name));
    } else {
        domain.shutdown()?;
        spinner.finish_with_message(format!("Sent shutdown signal to VM: {}", vm_name));
    }
    
    Ok(())
}

fn restart_vm_interactive() -> Result<()> {
    let conn = get_libvirt_connection()?;
    let domains = conn.list_all_domains(0)?;
    
    let mut choices = Vec::new();
    for domain in &domains {
        if let Ok(name) = domain.get_name() {
            if let Ok(state) = get_domain_state(domain) {
                if is_domain_running(state) {
                    choices.push((name, domain.clone()));
                }
            }
        }
    }
    
    if choices.is_empty() {
        println!("\n{}", style("No running VMs found").yellow());
        return Ok(());
    }
    
    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select VM to restart")
        .items(&choices.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>())
        .default(0)
        .interact()?;
    
    let (vm_name, domain) = &choices[selection];
    
    let force = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Force restart? (power cycle)")
        .default(false)
        .interact()?;
    
    let spinner = ProgressBar::new_spinner();
    spinner.set_message(format!("Restarting VM: {}...", vm_name));
    
    if force {
        domain.destroy()?;
    } else {
        domain.shutdown()?;
        // Wait for VM to shut down
        while !is_domain_shutoff(get_domain_state(domain)?) {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    
    // Start the VM
    domain.create()?;
    spinner.finish_with_message(format!("Successfully restarted VM: {}", vm_name));
    
    Ok(())
}

async fn connect_vm_interactive() -> Result<()> {
    let conn = get_libvirt_connection()?;
    let domains = conn.list_all_domains(0)?;
    
    let mut choices = Vec::new();
    for domain in &domains {
        if let Ok(name) = domain.get_name() {
            if let Ok(state) = get_domain_state(domain) {
                if is_domain_running(state) {
                    choices.push((name, domain.clone()));
                }
            }
        }
    }
    
    if choices.is_empty() {
        println!("\n{}", style("No running VMs found").yellow());
        return Ok(());
    }
    
    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Select VM to connect to")
        .items(&choices.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>())
        .default(0)
        .interact()?;
    
    let (vm_name, _) = &choices[selection];
    
    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("RDP Username")
        .interact_text()?;
    
    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("RDP Password")
        .allow_empty_password(true)
        .interact()?;
    
    let port: u16 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("RDP Port")
        .default(3389)
        .interact_text()?;
    
    connect_vm(vm_name, Some(username), Some(password), port)
}
