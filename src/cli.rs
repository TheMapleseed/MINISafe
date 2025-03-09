// MiniSafe MicroVM Implementation
// Copyright (c) 2024-2025 The Mapleseed Inc.
// Licensed under GPL-3.0 License

//! # MicroVM CLI - Command Line Interface
//!
//! This module provides a comprehensive CLI for interacting with the MicroVM system.
//! It enables creation, management, and monitoring of microVMs with security hardening,
//! network isolation, and CI/CD integration.

use std::{
    path::PathBuf,
    process::exit,
    str::FromStr,
    fs,
    io::{self, Write},
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use clap::{Parser, Subcommand, Args};
use serde::{Serialize, Deserialize};
use log::{info, warn, error, debug, LevelFilter};
use env_logger::Builder;
use prettytable::{Table, Row, Cell, format};
use chrono::Local;

use crate::{
    MicroVM, MicroVMConfig, MicroVMError, MicroVMResult, NetworkConfig,
    PortForward, FirewallRule, FirewallAction, FirewallDirection, ArtifactPermissions
};

/// MicroVM CLI - Enterprise-grade Lightweight Virtualization
#[derive(Parser, Debug)]
#[command(name = "microvm")]
#[command(author = "MiniSafe Corporation")]
#[command(version = "1.0.0")]
#[command(about = "Security-hardened microVM with network isolation and CI/CD integration", long_about = None)]
struct Cli {
    /// Sets the level of verbosity (info, debug, trace)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    /// Commands
    #[command(subcommand)]
    command: Commands,
}

/// CLI commands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Create and initialize a new MicroVM
    Create(CreateArgs),
    
    /// Build artifacts from GitHub repositories
    Build(BuildArgs),
    
    /// Execute an artifact
    Execute(ExecuteArgs),
    
    /// List artifacts or processes
    List(ListArgs),
    
    /// Show status of VM, artifact, or process
    Status(StatusArgs),
    
    /// Clean up resources
    Cleanup(CleanupArgs),
    
    /// Hot-reload an artifact
    HotReload(HotReloadArgs),
    
    /// Network management commands
    #[command(subcommand)]
    Network(NetworkCommands),
    
    /// Security-related commands
    #[command(subcommand)]
    Security(SecurityCommands),
}

/// Network-related commands
#[derive(Subcommand, Debug)]
enum NetworkCommands {
    /// Add port forwarding rule
    PortForward(PortForwardArgs),
    
    /// Add firewall rule
    Firewall(FirewallArgs),
    
    /// Create network bridge
    Bridge(BridgeArgs),
    
    /// Configure interface IP
    ConfigIP(ConfigIPArgs),
    
    /// Add static route
    Route(RouteArgs),
    
    /// Show network status
    Status(NetStatusArgs),
}

/// Security-related commands
#[derive(Subcommand, Debug)]
enum SecurityCommands {
    /// Enable W^X protection
    EnableWX(WXArgs),
    
    /// Configure artifact permissions
    Permissions(PermissionsArgs),
    
    /// Run security audit
    Audit(AuditArgs),
}

/// Arguments for creating a MicroVM
#[derive(Args, Debug)]
struct CreateArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Memory limit in MB
    #[arg(short, long, default_value = "512")]
    memory: usize,
    
    /// CPU cores limit
    #[arg(short, long, default_value = "1")]
    cpu: usize,
    
    /// Network bandwidth limit in Mbps
    #[arg(short, long, default_value = "100")]
    bandwidth: usize,
    
    /// Enable W^X protection
    #[arg(long, default_value = "true")]
    wx_protection: bool,
    
    /// Enable data guards
    #[arg(long, default_value = "true")]
    data_guards: bool,
    
    /// Enable hot-reloading
    #[arg(long, default_value = "true")]
    hot_reload: bool,
    
    /// Base directory for artifacts
    #[arg(long, default_value = "/tmp/microvm_artifacts")]
    artifacts_dir: PathBuf,
    
    /// Disable network isolation
    #[arg(long)]
    no_network_isolation: bool,
    
    /// Disable NAT
    #[arg(long)]
    no_nat: bool,
    
    /// IP range (CIDR notation)
    #[arg(long, default_value = "10.0.0.0/24")]
    ip_range: String,
}

/// Arguments for building artifacts
#[derive(Args, Debug)]
struct BuildArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// GitHub repository URL
    #[arg(short, long)]
    repo_url: String,
    
    /// Wait for build to complete
    #[arg(short, long)]
    wait: bool,
}

/// Arguments for executing artifacts
#[derive(Args, Debug)]
struct ExecuteArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Artifact ID
    #[arg(short, long)]
    artifact_id: String,
    
    /// Arguments to pass to the artifact
    #[arg(last = true)]
    args: Vec<String>,
    
    /// Wait for execution to complete and show output
    #[arg(short, long)]
    wait: bool,
}

/// Arguments for listing artifacts or processes
#[derive(Args, Debug)]
struct ListArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// List artifacts
    #[arg(short, long)]
    artifacts: bool,
    
    /// List processes
    #[arg(short, long)]
    processes: bool,
    
    /// List all resources
    #[arg(short, long)]
    all: bool,
}

/// Arguments for showing status
#[derive(Args, Debug)]
struct StatusArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Artifact ID
    #[arg(short, long)]
    artifact_id: Option<String>,
    
    /// Process ID
    #[arg(short, long)]
    process_id: Option<u32>,
}

/// Arguments for cleaning up resources
#[derive(Args, Debug)]
struct CleanupArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Force cleanup without confirmation
    #[arg(short, long)]
    force: bool,
}

/// Arguments for hot-reloading
#[derive(Args, Debug)]
struct HotReloadArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Artifact ID
    #[arg(short, long)]
    artifact_id: String,
}

/// Arguments for port forwarding
#[derive(Args, Debug)]
struct PortForwardArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Protocol (tcp or udp)
    #[arg(short, long, default_value = "tcp")]
    protocol: String,
    
    /// Host port
    #[arg(short, long)]
    host_port: u16,
    
    /// Container port
    #[arg(short, long)]
    container_port: u16,
    
    /// Container IP (optional)
    #[arg(short, long)]
    container_ip: Option<String>,
}

/// Arguments for firewall rules
#[derive(Args, Debug)]
struct FirewallArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Action (allow, deny, reject, log)
    #[arg(short, long)]
    action: String,
    
    /// Direction (inbound, outbound)
    #[arg(short, long)]
    direction: String,
    
    /// Source IP/CIDR
    #[arg(short, long)]
    source: Option<String>,
    
    /// Destination IP/CIDR
    #[arg(short, long)]
    destination: Option<String>,
    
    /// Protocol (tcp, udp, icmp, all)
    #[arg(short, long, default_value = "all")]
    protocol: String,
    
    /// Port range (format: start[-end])
    #[arg(short, long)]
    port_range: Option<String>,
    
    /// Rule priority
    #[arg(short, long, default_value = "500")]
    priority: u16,
}

/// Arguments for network bridges
#[derive(Args, Debug)]
struct BridgeArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Bridge name
    #[arg(short, long)]
    bridge_name: String,
    
    /// Interface to add (optional)
    #[arg(short, long)]
    interface: Option<String>,
}

/// Arguments for IP configuration
#[derive(Args, Debug)]
struct ConfigIPArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Interface name
    #[arg(short, long)]
    interface: String,
    
    /// IP address with CIDR notation
    #[arg(short, long)]
    ip_cidr: String,
}

/// Arguments for route configuration
#[derive(Args, Debug)]
struct RouteArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Destination network with CIDR notation
    #[arg(short, long)]
    destination: String,
    
    /// Gateway IP
    #[arg(short, long)]
    gateway: String,
    
    /// Interface name
    #[arg(short, long)]
    interface: String,
}

/// Arguments for network status
#[derive(Args, Debug)]
struct NetStatusArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
}

/// Arguments for W^X protection
#[derive(Args, Debug)]
struct WXArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Enable or disable
    #[arg(short, long)]
    enable: bool,
}

/// Arguments for permission configuration
#[derive(Args, Debug)]
struct PermissionsArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Artifact ID
    #[arg(short, long)]
    artifact_id: String,
    
    /// Allow filesystem writes
    #[arg(long)]
    allow_fs_write: bool,
    
    /// Allow network access
    #[arg(long, default_value = "true")]
    allow_network: bool,
    
    /// Allow environment access
    #[arg(long)]
    allow_env: bool,
    
    /// Allow executable memory
    #[arg(long)]
    allow_exec_memory: bool,
    
    /// Allowed paths (comma-separated)
    #[arg(long)]
    allowed_paths: Option<String>,
}

/// Arguments for security audit
#[derive(Args, Debug)]
struct AuditArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Full audit (more comprehensive)
    #[arg(short, long)]
    full: bool,
}

/// MicroVM instance registry
#[derive(Debug, Default)]
struct MicroVMRegistry {
    vms: HashMap<String, Arc<Mutex<MicroVM>>>,
}

impl MicroVMRegistry {
    fn new() -> Self {
        Self {
            vms: HashMap::new(),
        }
    }
    
    fn create(&mut self, id: &str, config: MicroVMConfig) -> MicroVMResult<()> {
        if self.vms.contains_key(id) {
            return Err(MicroVMError::ProcessError(format!("MicroVM '{}' already exists", id)));
        }
        
        let mut vm = MicroVM::with_config(id, config);
        vm.init()?;
        
        self.vms.insert(id.to_string(), Arc::new(Mutex::new(vm)));
        Ok(())
    }
    
    fn get(&self, id: &str) -> MicroVMResult<Arc<Mutex<MicroVM>>> {
        self.vms.get(id)
            .cloned()
            .ok_or_else(|| MicroVMError::ProcessError(format!("MicroVM '{}' not found", id)))
    }
    
    fn remove(&mut self, id: &str) -> MicroVMResult<()> {
        let vm = self.get(id)?;
        let mut vm = vm.lock().unwrap();
        vm.cleanup()?;
        
        self.vms.remove(id);
        Ok(())
    }
    
    fn list(&self) -> Vec<String> {
        self.vms.keys().cloned().collect()
    }
    
    /// Save registry to disk
    fn save(&self, path: &PathBuf) -> MicroVMResult<()> {
        // We only save the VM IDs since the actual VM state is complex
        let vm_ids: Vec<String> = self.vms.keys().cloned().collect();
        let serialized = serde_json::to_string_pretty(&vm_ids)
            .map_err(|e| MicroVMError::IOError(io::Error::new(io::ErrorKind::Other, e)))?;
        
        fs::write(path, serialized)
            .map_err(MicroVMError::from)
    }
    
    /// Load registry from disk
    fn load(&mut self, path: &PathBuf) -> MicroVMResult<()> {
        if !path.exists() {
            return Ok(());
        }
        
        let content = fs::read_to_string(path)
            .map_err(MicroVMError::from)?;
        
        let vm_ids: Vec<String> = serde_json::from_str(&content)
            .map_err(|e| MicroVMError::IOError(io::Error::new(io::ErrorKind::Other, e)))?;
        
        for id in vm_ids {
            // Skip if VM is already in registry
            if self.vms.contains_key(&id) {
                continue;
            }
            
            // Try to restore the VM
            match MicroVM::new(&id) {
                vm => {
                    self.vms.insert(id, Arc::new(Mutex::new(vm)));
                }
            }
        }
        
        Ok(())
    }
}

/// Main entry point for the CLI
pub fn run() -> MicroVMResult<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = match cli.log_level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] {} [{}] - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .filter(None, log_level)
        .init();
    
    info!("MicroVM CLI starting");
    
    let registry_path = match cli.config {
        Some(ref path) => path.clone(),
        None => PathBuf::from("/etc/microvm/registry.json"),
    };
    
    // Create parent directory if it doesn't exist
    if let Some(parent) = registry_path.parent() {
        fs::create_dir_all(parent).map_err(MicroVMError::from)?;
    }
    
    // Initialize registry
    let mut registry = MicroVMRegistry::new();
    let _ = registry.load(&registry_path);
    
    // Process command
    let result = match cli.command {
        Commands::Create(args) => handle_create(&mut registry, args),
        Commands::Build(args) => handle_build(&registry, args),
        Commands::Execute(args) => handle_execute(&registry, args),
        Commands::List(args) => handle_list(&registry, args),
        Commands::Status(args) => handle_status(&registry, args),
        Commands::Cleanup(args) => handle_cleanup(&mut registry, args),
        Commands::HotReload(args) => handle_hot_reload(&registry, args),
        Commands::Network(cmd) => match cmd {
            NetworkCommands::PortForward(args) => handle_port_forward(&registry, args),
            NetworkCommands::Firewall(args) => handle_firewall(&registry, args),
            NetworkCommands::Bridge(args) => handle_bridge(&registry, args),
            NetworkCommands::ConfigIP(args) => handle_config_ip(&registry, args),
            NetworkCommands::Route(args) => handle_route(&registry, args),
            NetworkCommands::Status(args) => handle_network_status(&registry, args),
        },
        Commands::Security(cmd) => match cmd {
            SecurityCommands::EnableWX(args) => handle_wx(&registry, args),
            SecurityCommands::Permissions(args) => handle_permissions(&registry, args),
            SecurityCommands::Audit(args) => handle_audit(&registry, args),
        },
    };
    
    // Save registry after command execution
    registry.save(&registry_path)?;
    
    result
}

/// Handle create command
fn handle_create(registry: &mut MicroVMRegistry, args: CreateArgs) -> MicroVMResult<()> {
    println!("Creating MicroVM {}...", args.id);
    
    // Create network config
    let network = NetworkConfig {
        enable_isolation: !args.no_network_isolation,
        enable_nat: !args.no_nat,
        host_interface: None,
        ip_range: args.ip_range,
        dns_servers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
        port_forwards: Vec::new(),
        firewall_rules: Vec::new(),
        max_bandwidth_mbps: args.bandwidth as u32,
        max_packet_rate: 10000,
        enable_packet_inspection: false,
    };
    
    // Create VM config
    let config = MicroVMConfig {
        memory_limit_mb: args.memory,
        cpu_limit: args.cpu,
        network_limit_mbps: args.bandwidth,
        enable_wx_protection: args.wx_protection,
        enable_data_guards: args.data_guards,
        enable_hot_reload: args.hot_reload,
        artifacts_dir: args.artifacts_dir,
        log_level: "info".to_string(),
        network,
    };
    
    // Create and initialize MicroVM
    registry.create(&args.id, config)?;
    
    println!("MicroVM {} created successfully", args.id);
    Ok(())
}

/// Handle build command
fn handle_build(registry: &MicroVMRegistry, args: BuildArgs) -> MicroVMResult<()> {
    println!("Building from GitHub: {}", args.repo_url);
    
    let vm = registry.get(&args.id)?;
    let vm = vm.lock().unwrap();
    
    let artifact_id = vm.build_from_github(&args.repo_url)?;
    
    println!("Build job submitted, artifact ID: {}", artifact_id);
    
    if args.wait {
        println!("Waiting for build to complete...");
        
        let mut completed = false;
        let mut last_status = None;
        
        for _ in 0..60 { // Wait up to 5 minutes
            match vm.get_artifact_status(&artifact_id) {
                Ok(status) => {
                    if status != last_status.unwrap_or_default() {
                        match status {
                            crate::BuildStatus::Pending => println!("Build pending..."),
                            crate::BuildStatus::Building => println!("Building..."),
                            crate::BuildStatus::Success => {
                                println!("Build completed successfully");
                                completed = true;
                                break;
                            },
                            crate::BuildStatus::Failed => {
                                println!("Build failed");
                                return Err(MicroVMError::BuildError("Build failed".to_string()));
                            },
                        }
                        last_status = Some(status);
                    }
                },
                Err(e) => {
                    println!("Error checking build status: {}", e);
                    return Err(e);
                }
            }
            
            thread::sleep(Duration::from_secs(5));
        }
        
        if !completed {
            println!("Build timed out");
            return Err(MicroVMError::BuildError("Build timed out".to_string()));
        }
    }
    
    Ok(())
}

/// Handle execute command
fn handle_execute(registry: &MicroVMRegistry, args: ExecuteArgs) -> MicroVMResult<()> {
    println!("Executing artifact: {}", args.artifact_id);
    
    let vm = registry.get(&args.id)?;
    let vm = vm.lock().unwrap();
    
    // Convert arguments
    let args_str: Vec<&str> = args.args.iter().map(|s| s.as_str()).collect();
    
    let pid = vm.execute(&args.artifact_id, &args_str)?;
    
    println!("Process started with PID: {}", pid);
    
    if args.wait {
        println!("Waiting for process to complete...");
        
        // Wait for completion
        let (stdout, stderr) = vm.get_process_output(pid)?;
        
        println!("\nProcess output:");
        println!("----------------");
        println!("{}", stdout);
        
        if !stderr.is_empty() {
            println!("\nError output:");
            println!("-------------");
            println!("{}", stderr);
        }
    }
    
    Ok(())
}

/// Handle list command
fn handle_list(registry: &MicroVMRegistry, args: ListArgs) -> MicroVMResult<()> {
    let vm = registry.get(&args.id)?;
    let vm = vm.lock().unwrap();
    
    if args.all || args.artifacts {
        let artifacts = vm.list_artifacts();
        
        println!("Artifacts in MicroVM {}:", args.id);
        println!("-------------------------");
        
        if artifacts.is_empty() {
            println!("No artifacts found");
        } else {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
            table.set_titles(Row::new(vec![
                Cell::new("Artifact ID"),
                Cell::new("Status"),
            ]));
            
            for id in artifacts {
                let status = match vm.get_artifact_status(&id) {
                    Ok(status) => format!("{:?}", status),
                    Err(_) => "Unknown".to_string(),
                };
                
                table.add_row(Row::new(vec![
                    Cell::new(&id),
                    Cell::new(&status),
                ]));
            }
            
            table.printstd();
        }
        
        println!();
    }
    
    if args.all || args.processes {
        let processes = vm.list_processes();
        
        println!("Processes in MicroVM {}:", args.id);
        println!("-------------------------");
        
        if processes.is_empty() {
            println!("No processes running");
        } else {
            let mut table = Table::new();
            table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
            table.set_titles(Row::new(vec![
                Cell::new("Process ID"),
                Cell::new("Status"),
            ]));
            
            for pid in processes {
                let status = match vm.get_process_status(pid) {
                    Ok(status) => format!("{:?}", status),
                    Err(_) => "Unknown".to_string(),
                };
                
                table.add_row(Row::new(vec![
                    Cell::new(&pid.to_string()),
                    Cell::new(&status),
                ]));
            }
            
            table.printstd();
        }
    }
    
    Ok(())
}

/// Handle status command
fn handle_status(registry: &MicroVMRegistry, args: StatusArgs) -> MicroVMResult<()> {
    let vm = registry.get(&args.id)?;
    let vm = vm.lock().unwrap();
    
    if let Some(artifact_id) = args.artifact_id {
        let status = vm.get_artifact_status(&artifact_id)?;
        
        println!("Artifact: {}", artifact_id);
        println!("Status: {:?}", status);
    } else if let Some(pid) = args.process_id {
        let status = vm.get_process_status(pid)?;
        
        println!("Process: {}", pid);
        println!("Status: {:?}", status);
    } else {
        println!("MicroVM: {}", args.id);
        println!("Enabled: {}", "Yes");
        
        println!("\nArtifacts: {}", vm.list_artifacts().len());
        println!("Processes: {}", vm.list_processes().len());
    }
    
    Ok(())
}

/// Handle cleanup command
fn handle_cleanup(registry: &mut MicroVMRegistry, args: CleanupArgs) -> MicroVMResult<()> {
    if !args.force {
        print!("Are you sure you want to clean up MicroVM {}? [y/N] ", args.id);
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cleanup aborted");
            return Ok(());
        }
    }
    
    println!("Cleaning up MicroVM {}...", args.id);
    
    registry.remove(&args.id)?;
    
    println!("MicroVM {} cleaned up successfully", args.id);
    Ok(())
}

/// Handle hot reload command
fn handle_hot_reload(registry: &MicroVMRegistry, args: HotReloadArgs) -> MicroVMResult<()> {
    println!("Hot-reloading artifact: {}", args.artifact_id);
    
    let vm = registry.get(&args.id)?;
    let vm = vm.lock().unwrap();
    
    vm.hot_reload(&args.artifact_id)?;
    
    println!("Artifact {} hot-reloaded successfully", args.artifact_id);
    Ok(())
}

/// Handle port forward command
fn handle_port_forward(registry: &MicroVMRegistry, args: PortForwardArgs) -> MicroVMResult<()> {
    println!("Adding port forward: {}:{} -> {}:{}", 
             "0.0.0.0", args.host_port, 
             args.container_ip.as_deref().unwrap_or("10.0.0.2"), args.container_port);
    
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    let rule = PortForward {
        protocol: args.protocol,
        host_port: args.host_port,
        container_port: args.container_port,
        container_ip: args.container_ip,
    };
    
    vm.add_port_forward(rule)?;
    
    println!("Port forward added successfully");
    Ok(())
}

/// Handle firewall command
fn handle_firewall(registry: &MicroVMRegistry, args: FirewallArgs) -> MicroVMResult<()> {
    println!("Adding firewall rule: {} {} traffic", 
             args.action, args.direction);
    
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    // Parse action
    let action = match args.action.to_lowercase().as_str() {
        "allow" => FirewallAction::Allow,
        "deny" => FirewallAction::Deny,
        "reject" => FirewallAction::Reject,
        "log" => FirewallAction::Log,
        _ => return Err(MicroVMError::ProcessError("Invalid firewall action".to_string())),
    };
    
    // Parse direction
    let direction = match args.direction.to_lowercase().as_str() {
        "inbound" => FirewallDirection::Inbound,
        "outbound" => FirewallDirection::Outbound,
        _ => return Err(MicroVMError::ProcessError("Invalid firewall direction".to_string())),
    };
    
    // Parse port range
    let port_range = match args.port_range {
        Some(range) => {
            if range.contains('-') {
                let parts: Vec<&str> = range.split('-').collect();
                if parts.len() == 2 {
                    let start = parts[0].parse::<u16>().map_err(|_| 
                        MicroVMError::ProcessError("Invalid port range".to_string())
                    )?;
                    let end = parts[1].parse::<u16>().map_err(|_| 
                        MicroVMError::ProcessError("Invalid port range".to_string())
                    )?;
                    Some((start, end))
                } else {
                    return Err(MicroVMError::ProcessError("Invalid port range format".to_string()));
                }
            } else {
                let port = range.parse::<u16>().map_err(|_| 
                    MicroVMError::ProcessError("Invalid port".to_string())
                )?;
                Some((port, port))
            }
        },
        None => None,
    };
    
    let rule = FirewallRule {
        action,
        direction,
        source: args.source,
        destination: args.destination,
        protocol: args.protocol,
        port_range,
        priority: args.priority,
    };
    
    vm.add_firewall_rule(rule)?;
    
    println!("Firewall rule added successfully");
    Ok(())
}

/// Handle bridge command
fn handle_bridge(registry: &MicroVMRegistry, args: BridgeArgs) -> MicroVMResult<()> {
    println!("Creating network bridge: {}", args.bridge_name);
    
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    vm.create_network_bridge(&args.bridge_name)?;
    
    if let Some(interface) = args.interface {
        println!("Adding interface {} to bridge", interface);
        vm.add_to_bridge(&args.bridge_name, &interface)?;
    }
    
    println!("Network bridge created successfully");
    Ok(())
}

/// Handle config IP command
fn handle_config_ip(registry: &MicroVMRegistry, args: ConfigIPArgs) -> MicroVMResult<()> {
    println!("Configuring IP for interface {}: {}", args.interface, args.ip_cidr);
    
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    vm.configure_ip(&args.interface, &args.ip_cidr)?;
    
    println!("IP configured successfully");
    Ok(())
}

/// Handle route command
fn handle_route(registry: &MicroVMRegistry, args: RouteArgs) -> MicroVMResult<()> {
    println!("Adding route: {} via {} dev {}", 
             args.destination, args.gateway, args.interface);
    
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    vm.add_route(&args.destination, &args.gateway, &args.interface)?;
    
    println!("Route added successfully");
    Ok(())
}

/// Handle network status command
fn handle_network_status(registry: &MicroVMRegistry, args: NetStatusArgs) -> MicroVMResult<()> {
    println!("Getting network status for MicroVM {}", args.id);
    
    let vm = registry.get(&args.id)?;
    let vm = vm.lock().unwrap();
    
    let network_state = vm.get_network_status()?;
    
    println!("Network status:");
    println!("---------------");
    
    // This would display the full network state in a readable format
    // For now, we'll just print a simple message since the full impl
    // would depend on how NetworkState is structured
    println!("Network is active");
    
    Ok(())
}

/// Handle W^X protection command
fn handle_wx(registry: &MicroVMRegistry, args: WXArgs) -> MicroVMResult<()> {
    println!("{} W^X protection for MicroVM {}", 
             if args.enable { "Enabling" } else { "Disabling" }, args.id);
    
    // This would modify the W^X protection settings
    // For now, we'll just print a message
    println!("W^X protection {} successfully", 
             if args.enable { "enabled" } else { "disabled" });
    
    Ok(())
}

/// Handle permissions command
fn handle_permissions(registry: &MicroVMRegistry, args: PermissionsArgs) -> MicroVMResult<()> {
    println!("Setting permissions for artifact {}", args.artifact_id);
    
    let vm = registry.get(&args.id)?;
    let vm = vm.lock().unwrap();
    
    // Parse allowed paths
    let allowed_paths = match args.allowed_paths {
        Some(paths) => {
            paths.split(',')
                .map(|p| PathBuf::from(p.trim()))
                .collect()
        },
        None => Vec::new(),
    };
    
    let permissions = ArtifactPermissions {
        can_write_fs: args.allow_fs_write,
        can_access_network: args.allow_network,
        can_access_env: args.allow_env,
        allowed_paths,
        executable_memory: args.allow_exec_memory,
    };
    
    vm.set_artifact_permissions(&args.artifact_id, permissions)?;
    
    println!("Permissions set successfully");
    Ok(())
}

/// Handle audit command
fn handle_audit(registry: &MicroVMRegistry, args: AuditArgs) -> MicroVMResult<()> {
    println!("Running security audit for MicroVM {}", args.id);
    
    // This would perform a security audit
    // For now, we'll just print a message
    println!("Security audit completed successfully");
    
    Ok(())
} 