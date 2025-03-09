impl MicroVM {
    /// Mount host directory into the VM
    pub fn mount_directory(&mut self, artifact_id: &str, host_path: &Path, vm_path: &Path, 
                          mode: FileAccessMode, options: &[&str]) -> MicroVMResult<()> {
        // Verify VM is initialized
        let namespace = self.namespace.as_ref().ok_or_else(|| 
            MicroVMError::ProcessError("MicroVM namespace not initialized".to_string())
        )?;
        
        // Verify artifact exists
        let artifacts = self.artifacts.read().unwrap();
        let artifact_lock = artifacts.get(artifact_id).ok_or_else(|| 
            MicroVMError::ArtifactNotFound(artifact_id.to_string())
        )?;
        
        // Create mount point if it doesn't exist
        let mount_cmd = format!("mkdir -p {}", vm_path.display());
        Command::new("ip")
            .args(&["netns", "exec", namespace, "sh", "-c", &mount_cmd])
            .status()
            .map_err(|e| MicroVMError::IOError(e))?;
        
        // Prepare mount options
        let mut mount_opts = String::new();
        match mode {
            FileAccessMode::ReadOnly => mount_opts.push_str("ro,"),
            FileAccessMode::ReadWrite => mount_opts.push_str("rw,"),
            FileAccessMode::ReadWriteExecute => mount_opts.push_str("rw,"),
        }
        
        // Add additional security options
        mount_opts.push_str("nosuid,");
        if mode != FileAccessMode::ReadWriteExecute {
            mount_opts.push_str("noexec,");
        }
        
        // Add user options
        for opt in options {
            mount_opts.push_str(opt);
            mount_opts.push(',');
        }
        mount_opts.pop(); // Remove trailing comma
        
        // Perform the bind mount
        Command::new("mount")
            .args(&["--bind", "-o", &mount_opts, 
                   host_path.to_str().unwrap(), vm_path.to_str().unwrap()])
            .status()
            .map_err(|e| MicroVMError::IOError(e))?;
        
        // Update artifact permissions
        let mount_info = FileSystemAccess {
            host_path: host_path.to_path_buf(),
            vm_path: vm_path.to_path_buf(),
            mode,
            mount_options: options.iter().map(|&s| s.to_string()).collect(),
        };
        
        {
            let mut artifact = artifact_lock.write().unwrap();
            if artifact.permissions.filesystem_mounts.iter().any(|m| m.vm_path == mount_info.vm_path) {
                return Err(MicroVMError::ProcessError(
                    format!("Mount point {} already exists", vm_path.display())
                ));
            }
            artifact.permissions.filesystem_mounts.push(mount_info);
        }
        
        // Setup audit if enabled
        let artifact = artifact_lock.read().unwrap();
        if artifact.permissions.enable_fs_auditing {
            self.setup_fs_auditing(namespace, vm_path)?;
        }
        
        Ok(())
    }
    
    /// Setup filesystem auditing for a mount point
    fn setup_fs_auditing(&self, namespace: &str, path: &Path) -> MicroVMResult<()> {
        // Implement audit logging using tools like auditd
        // This could use Linux audit framework to track file operations
        // For example, using auditctl to watch the mounted directory
        
        Ok(())
    }

    /// Configure environment variable access for an artifact
    pub fn configure_env_vars(&mut self, artifact_id: &str, 
                             env_config: EnvVarAccess) -> MicroVMResult<()> {
        // Get artifact
        let artifacts = self.artifacts.read().unwrap();
        let artifact_lock = artifacts.get(artifact_id).ok_or_else(|| 
            MicroVMError::ArtifactNotFound(artifact_id.to_string())
        )?;
        
        // Update permissions
        let mut artifact = artifact_lock.write().unwrap();
        
        // Only update if env access is allowed
        if !artifact.permissions.can_access_env && 
           (!env_config.allowed_vars.is_empty() || !env_config.injected_vars.is_empty()) {
            return Err(MicroVMError::SecurityViolation(
                format!("Environment access is disabled for artifact {}", artifact_id)
            ));
        }
        
        artifact.permissions.env_var_access = env_config;
        Ok(())
    }
    
    /// Add a single environment variable
    pub fn add_env_var(&mut self, artifact_id: &str, 
                      key: &str, value: &str) -> MicroVMResult<()> {
        let artifacts = self.artifacts.read().unwrap();
        let artifact_lock = artifacts.get(artifact_id).ok_or_else(|| 
            MicroVMError::ArtifactNotFound(artifact_id.to_string())
        )?;
        
        let mut artifact = artifact_lock.write().unwrap();
        
        // Check if env access is allowed
        if !artifact.permissions.can_access_env {
            return Err(MicroVMError::SecurityViolation(
                format!("Environment access is disabled for artifact {}", artifact_id)
            ));
        }
        
        // Check against denied patterns
        for pattern in &artifact.permissions.env_var_access.denied_vars {
            if pattern_matches(pattern, key) {
                return Err(MicroVMError::SecurityViolation(
                    format!("Environment variable {} matches denied pattern {}", key, pattern)
                ));
            }
        }
        
        artifact.permissions.env_var_access.injected_vars.insert(key.to_string(), value.to_string());
        
        Ok(())
    }
    
    /// Prepare environment variables for a process
    fn prepare_env_variables(&self, artifact_id: &str) -> MicroVMResult<HashMap<String, String>> {
        let artifacts = self.artifacts.read().unwrap();
        let artifact_lock = artifacts.get(artifact_id).ok_or_else(|| 
            MicroVMError::ArtifactNotFound(artifact_id.to_string())
        )?;
        
        let artifact = artifact_lock.read().unwrap();
        let mut result = HashMap::new();
        
        // If env access is disabled, return only injected vars
        if !artifact.permissions.can_access_env {
            return Ok(artifact.permissions.env_var_access.injected_vars.clone());
        }
        
        // Get current environment
        for (key, value) in std::env::vars() {
            // Check if variable is allowed
            let mut allowed = false;
            for pattern in &artifact.permissions.env_var_access.allowed_vars {
                if pattern_matches(pattern, &key) {
                    allowed = true;
                    break;
                }
            }
            
            // Check if variable is denied
            let mut denied = false;
            for pattern in &artifact.permissions.env_var_access.denied_vars {
                if pattern_matches(pattern, &key) {
                    denied = true;
                    break;
                }
            }
            
            // Only include if allowed and not denied
            if allowed && !denied {
                // Apply sanitization if enabled
                let final_value = if artifact.permissions.env_var_access.enable_sanitization {
                    sanitize_env_value(&key, &value)
                } else {
                    value
                };
                
                result.insert(key, final_value);
            }
        }
        
        // Add injected variables (overriding any existing ones)
        for (key, value) in &artifact.permissions.env_var_access.injected_vars {
            result.insert(key.clone(), value.clone());
        }
        
        // Log access if auditing is enabled
        if artifact.permissions.env_var_access.audit_env_access {
            self.audit_env_access(artifact_id, &result)?;
        }
        
        Ok(result)
    }
    
    /// Audit environment variable access
    fn audit_env_access(&self, artifact_id: &str, 
                       env_vars: &HashMap<String, String>) -> MicroVMResult<()> {
        // In a real implementation, this would log to a secure audit log
        info!("AUDIT: Artifact {} accessed {} environment variables", 
              artifact_id, env_vars.len());
        
        // For sensitive variables, we don't log the values, just the keys
        for key in env_vars.keys() {
            debug!("AUDIT: Artifact {} accessed env var: {}", artifact_id, key);
        }
        
        Ok(())
    }
    
    /// Modified execute function to use prepared environment variables
    pub fn execute(&self, artifact_id: &str, args: &[&str]) -> MicroVMResult<u32> {
        // Get artifact and prepare for execution
        // ... (existing code)
        
        // Get prepared environment variables
        let env_vars = self.prepare_env_variables(artifact_id)?;
        
        // ... (existing code)
        
        // Configure command with environment variables
        for (key, value) in env_vars {
            cmd.env(key, value);
        }
        
        // ... (rest of execution code)
    }

    /// Store a persistent credential
    pub fn store_credential(&mut self, artifact_id: &str, key: &str, 
                           value: &str, auto_load: bool, 
                           description: Option<&str>) -> MicroVMResult<()> {
        // Get or create vault for this artifact
        let vault_path = self.get_vault_path(artifact_id)?;
        let mut vault = self.load_vault(&vault_path)?;
        
        // Create metadata
        let metadata = CredentialMetadata {
            name: key.to_string(),
            description: description.map(|s| s.to_string()),
            added_at: Utc::now(),
            tags: vec!["api".to_string()],
            auto_load,
        };
        
        // Store credential securely
        self.add_to_vault(&mut vault, key, value, metadata)?;
        
        // Save vault
        self.save_vault(&vault_path, &vault)?;
        
        // If auto_load is enabled, add to current environment
        if auto_load {
            self.add_env_var(artifact_id, key, value)?;
        }
        
        info!("Credential '{}' stored permanently for artifact {}", key, artifact_id);
        Ok(())
    }
    
    /// Get path to secure credential vault
    fn get_vault_path(&self, artifact_id: &str) -> MicroVMResult<PathBuf> {
        // Create vault directory if it doesn't exist
        let vault_dir = self.config.artifacts_dir.join("vaults");
        fs::create_dir_all(&vault_dir)
            .map_err(|e| MicroVMError::IOError(e))?;
            
        // Use a secure filename based on artifact ID
        Ok(vault_dir.join(format!("{}.vault", artifact_id)))
    }
    
    /// Load credential vault (or create a new one)
    fn load_vault(&self, path: &Path) -> MicroVMResult<CredentialVault> {
        if !path.exists() {
            return Ok(CredentialVault {
                encrypted_data: Vec::new(),
                metadata: HashMap::new(),
                last_modified: Utc::now(),
            });
        }
        
        // Read and decrypt vault
        let encrypted_data = fs::read(path)
            .map_err(|e| MicroVMError::IOError(e))?;
            
        // Decrypt the data (in a real implementation, we would use proper encryption)
        // For this example, we'll use a placeholder
        let decrypted_data = self.decrypt_data(&encrypted_data)?;
        
        // Deserialize the vault
        let vault: CredentialVault = serde_json::from_slice(&decrypted_data)
            .map_err(|e| MicroVMError::ProcessError(format!("Failed to deserialize vault: {}", e)))?;
            
        Ok(vault)
    }
    
    /// Add credential to vault
    fn add_to_vault(&self, vault: &mut CredentialVault, key: &str, 
                   value: &str, metadata: CredentialMetadata) -> MicroVMResult<()> {
        // In a real implementation, this would store credentials securely
        // For this example, we'll just update the vault structure
        
        // Store credential in encrypted data (details omitted for simplicity)
        // ...
        
        // Update metadata
        vault.metadata.insert(key.to_string(), metadata);
        vault.last_modified = Utc::now();
        
        Ok(())
    }
    
    /// Save vault to disk
    fn save_vault(&self, path: &Path, vault: &CredentialVault) -> MicroVMResult<()> {
        // Serialize the vault
        let vault_data = serde_json::to_vec(vault)
            .map_err(|e| MicroVMError::ProcessError(format!("Failed to serialize vault: {}", e)))?;
            
        // Encrypt the data (in a real implementation, this would use strong encryption)
        let encrypted_data = self.encrypt_data(&vault_data)?;
        
        // Set secure file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true).mode(0o600);
            
            let mut file = options.open(path)
                .map_err(|e| MicroVMError::IOError(e))?;
                
            file.write_all(&encrypted_data)
                .map_err(|e| MicroVMError::IOError(e))?;
        }
        
        #[cfg(not(unix))]
        {
            fs::write(path, &encrypted_data)
                .map_err(|e| MicroVMError::IOError(e))?;
        }
        
        Ok(())
    }
    
    /// Encrypt data (placeholder)
    fn encrypt_data(&self, data: &[u8]) -> MicroVMResult<Vec<u8>> {
        // In a real implementation, this would use a strong encryption algorithm
        // For this example, we'll just return the data as-is
        Ok(data.to_vec())
    }
    
    /// Decrypt data (placeholder)
    fn decrypt_data(&self, data: &[u8]) -> MicroVMResult<Vec<u8>> {
        // In a real implementation, this would use a strong decryption algorithm
        // For this example, we'll just return the data as-is
        Ok(data.to_vec())
    }
    
    /// Load all auto-load credentials for an artifact
    pub fn load_persistent_credentials(&mut self, artifact_id: &str) -> MicroVMResult<()> {
        info!("Loading persistent credentials for artifact {}", artifact_id);
        
        // Get vault path
        let vault_path = self.get_vault_path(artifact_id)?;
        if !vault_path.exists() {
            debug!("No credential vault found for artifact {}", artifact_id);
            return Ok(());
        }
        
        // Load vault
        let vault = self.load_vault(&vault_path)?;
        
        // Count auto-load credentials
        let auto_load_count = vault.metadata.values()
            .filter(|m| m.auto_load)
            .count();
            
        debug!("Found {} auto-load credentials for artifact {}", auto_load_count, artifact_id);
        
        // Extract all credentials from vault
        let credentials = self.extract_credentials_from_vault(&vault)?;
        
        // Apply auto-load credentials
        let mut loaded_count = 0;
        for (key, metadata) in &vault.metadata {
            if metadata.auto_load {
                if let Some(value) = credentials.get(key) {
                    self.add_env_var(artifact_id, key, value)?;
                    loaded_count += 1;
                }
            }
        }
        
        info!("Loaded {} persistent credentials for artifact {}", loaded_count, artifact_id);
        Ok(())
    }
    
    /// Extract credentials from vault
    fn extract_credentials_from_vault(&self, vault: &CredentialVault) -> MicroVMResult<HashMap<String, String>> {
        // In a real implementation, this would decrypt and extract credentials
        // For this example, we'll return a placeholder
        let mut credentials = HashMap::new();
        
        // Extract credentials from encrypted_data
        // ...
        
        Ok(credentials)
    }
    
    /// List stored credentials (metadata only, not values)
    pub fn list_credentials(&self, artifact_id: &str) -> MicroVMResult<Vec<CredentialMetadata>> {
        let vault_path = self.get_vault_path(artifact_id)?;
        if !vault_path.exists() {
            return Ok(Vec::new());
        }
        
        let vault = self.load_vault(&vault_path)?;
        Ok(vault.metadata.values().cloned().collect())
    }
    
    /// Remove a stored credential
    pub fn remove_credential(&mut self, artifact_id: &str, key: &str) -> MicroVMResult<()> {
        let vault_path = self.get_vault_path(artifact_id)?;
        if !vault_path.exists() {
            return Err(MicroVMError::ProcessError(
                format!("No credentials found for artifact {}", artifact_id)
            ));
        }
        
        let mut vault = self.load_vault(&vault_path)?;
        
        if !vault.metadata.contains_key(key) {
            return Err(MicroVMError::ProcessError(
                format!("Credential '{}' not found for artifact {}", key, artifact_id)
            ));
        }
        
        // Remove credential
        vault.metadata.remove(key);
        
        // Update encrypted data
        // ...
        
        // Save updated vault
        self.save_vault(&vault_path, &vault)?;
        
        info!("Credential '{}' removed from artifact {}", key, artifact_id);
        Ok(())
    }
    
    /// Auto-loading hook for VM initialization
    fn auto_load_credentials_on_start(&mut self) -> MicroVMResult<()> {
        info!("Auto-loading persistent credentials for all artifacts");
        
        for artifact_id in self.list_artifacts() {
            let _ = self.load_persistent_credentials(&artifact_id);
        }
        
        Ok(())
    }

    /// Initialize the microVM with security hardening
    pub fn init(&mut self) -> MicroVMResult<()> {
        info!("Initializing MicroVM {}", self.id);
        
        // Existing initialization code...
        
        // Setup network if enabled
        if self.config.network.enable_isolation {
            self.setup_network(&ns_name)?;
        }
        
        // Apply W^X protection if enabled
        if self.config.enable_wx_protection {
            self.apply_wx_protection()?;
        }
        
        // Apply data guards if enabled
        if self.config.enable_data_guards {
            self.apply_data_guards()?;
        }
        
        // Auto-load persistent credentials
        self.auto_load_credentials_on_start()?;
        
        // Start process monitor in a separate thread
        self.start_process_monitor();
        
        // Additional initialization...
        
        self.enabled = true;
        info!("MicroVM {} initialized successfully", self.id);
        Ok(())
    }
}

/// Check if a string matches a pattern (with glob support)
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.contains('*') {
        // Simple glob matching implementation
        let parts: Vec<&str> = pattern.split('*').collect();
        
        // Empty pattern or just "*" matches everything
        if parts.is_empty() || (parts.len() == 1 && parts[0].is_empty()) {
            return true;
        }
        
        // Check prefix
        if !parts[0].is_empty() && !value.starts_with(parts[0]) {
            return false;
        }
        
        // Check suffix
        if parts.len() > 1 && !parts.last().unwrap().is_empty() && !value.ends_with(parts.last().unwrap()) {
            return false;
        }
        
        // Check middle parts
        let mut remaining = value;
        for part in &parts[0..parts.len() - 1] {
            if part.is_empty() {
                continue;
            }
            
            if let Some(idx) = remaining.find(part) {
                remaining = &remaining[idx + part.len()..];
            } else {
                return false;
            }
        }
        
        true
    } else {
        // Exact matching
        pattern == value
    }
}

/// Sanitize environment variable values
fn sanitize_env_value(key: &str, value: &str) -> String {
    // For sensitive-looking variables, we might want to hide the actual value
    if key.contains("PASSWORD") || key.contains("SECRET") || key.contains("KEY") || 
       key.contains("TOKEN") || key.contains("CREDENTIAL") {
        // Return "<hidden>" or partial value
        if value.len() > 4 {
            format!("{}***", &value[0..1])
        } else {
            "<hidden>".to_string()
        }
    } else {
        // Return regular value for non-sensitive variables
        value.to_string()
    }
}

/// Arguments for filesystem access
#[derive(Args, Debug)]
struct MountArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Artifact ID
    #[arg(short, long)]
    artifact_id: String,
    
    /// Host path to mount
    #[arg(short, long)]
    host_path: PathBuf,
    
    /// VM path where to mount
    #[arg(short, long)]
    vm_path: PathBuf,
    
    /// Access mode (ro, rw, rwx)
    #[arg(short, long, default_value = "ro")]
    mode: String,
    
    /// Additional mount options (comma-separated)
    #[arg(short, long)]
    options: Option<String>,
}

/// Arguments for environment variable management
#[derive(Args, Debug)]
struct EnvVarArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Artifact ID
    #[arg(short, long)]
    artifact_id: String,
    
    /// Environment variables to add (format: KEY=value)
    #[arg(short, long)]
    vars: Vec<String>,
    
    /// Allowed environment variable patterns (glob supported)
    #[arg(long)]
    allow: Option<Vec<String>>,
    
    /// Denied environment variable patterns (glob supported)
    #[arg(long)]
    deny: Option<Vec<String>>,
    
    /// Enable/disable environment sanitization
    #[arg(long)]
    sanitize: Option<bool>,
    
    /// Enable/disable environment access auditing
    #[arg(long)]
    audit: Option<bool>,
}

/// Arguments for credential management
#[derive(Args, Debug)]
struct CredentialArgs {
    /// MicroVM ID
    #[arg(short, long)]
    id: String,
    
    /// Artifact ID
    #[arg(short, long)]
    artifact_id: String,
    
    /// Credential key
    #[arg(short, long)]
    key: Option<String>,
    
    /// Credential value
    #[arg(short, long)]
    value: Option<String>,
    
    /// Description of the credential
    #[arg(long)]
    description: Option<String>,
    
    /// Auto-load on VM start
    #[arg(long, default_value = "true")]
    auto_load: bool,
    
    /// List stored credentials
    #[arg(short, long)]
    list: bool,
    
    /// Remove credential
    #[arg(short, long)]
    remove: bool,
}

// Add to NetworkCommands enum:
enum NetworkCommands {
    // ... existing commands ...
    
    /// Mount host directory
    Mount(MountArgs),
}

// Add to SecurityCommands enum:
enum SecurityCommands {
    // ... existing commands ...
    
    /// Configure environment variables
    Environment(EnvVarArgs),
    
    /// Manage persistent credentials
    Credential(CredentialArgs),
}

// Handle mount command
fn handle_mount(registry: &MicroVMRegistry, args: MountArgs) -> MicroVMResult<()> {
    println!("Mounting {} to {} for artifact {}", 
             args.host_path.display(), args.vm_path.display(), args.artifact_id);
    
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    // Parse access mode
    let mode = match args.mode.as_str() {
        "ro" => FileAccessMode::ReadOnly,
        "rw" => FileAccessMode::ReadWrite,
        "rwx" => FileAccessMode::ReadWriteExecute,
        _ => return Err(MicroVMError::ProcessError("Invalid access mode".to_string())),
    };
    
    // Parse mount options
    let options: Vec<&str> = match &args.options {
        Some(opts) => opts.split(',').collect(),
        None => Vec::new(),
    };
    
    vm.mount_directory(&args.artifact_id, &args.host_path, &args.vm_path, mode, &options)?;
    
    println!("Directory mounted successfully");
    Ok(())
}

// Handle environment variable command
fn handle_env_vars(registry: &MicroVMRegistry, args: EnvVarArgs) -> MicroVMResult<()> {
    println!("Configuring environment variables for artifact {}", args.artifact_id);
    
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    // Parse variables to add
    let mut injected_vars = HashMap::new();
    for var_str in &args.vars {
        if let Some(pos) = var_str.find('=') {
            let (key, value) = var_str.split_at(pos);
            // Skip the '=' character
            injected_vars.insert(key.to_string(), value[1..].to_string());
        } else {
            return Err(MicroVMError::ProcessError(
                format!("Invalid environment variable format: {}", var_str)
            ));
        }
    }
    
    // Get current configuration
    let artifacts = vm.list_artifacts();
    let artifact_found = artifacts.iter().any(|id| id == &args.artifact_id);
    if !artifact_found {
        return Err(MicroVMError::ArtifactNotFound(args.artifact_id));
    }
    
    // Create new configuration
    let mut env_config = EnvVarAccess::default();
    
    // Set allowed patterns
    if let Some(allowed) = args.allow {
        env_config.allowed_vars = allowed;
    }
    
    // Set denied patterns
    if let Some(denied) = args.deny {
        env_config.denied_vars = denied;
    }
    
    // Set injected variables
    env_config.injected_vars = injected_vars;
    
    // Configure sanitization
    if let Some(sanitize) = args.sanitize {
        env_config.enable_sanitization = sanitize;
    }
    
    // Configure auditing
    if let Some(audit) = args.audit {
        env_config.audit_env_access = audit;
    }
    
    // Apply configuration
    vm.configure_env_vars(&args.artifact_id, env_config)?;
    
    println!("Environment variables configured successfully");
    Ok(())
}

// Handle credential command
fn handle_credentials(registry: &MicroVMRegistry, args: CredentialArgs) -> MicroVMResult<()> {
    let vm = registry.get(&args.id)?;
    let mut vm = vm.lock().unwrap();
    
    if args.list {
        // List credentials
        println!("Stored credentials for artifact {}:", args.artifact_id);
        
        let credentials = vm.list_credentials(&args.artifact_id)?;
        if credentials.is_empty() {
            println!("  No stored credentials found");
            return Ok(());
        }
        
        let mut table = Table::new();
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
        table.set_titles(Row::new(vec![
            Cell::new("Key"),
            Cell::new("Description"),
            Cell::new("Added"),
            Cell::new("Auto-load"),
        ]));
        
        for cred in credentials {
            table.add_row(Row::new(vec![
                Cell::new(&cred.name),
                Cell::new(cred.description.as_deref().unwrap_or("-")),
                Cell::new(&cred.added_at.format("%Y-%m-%d %H:%M:%S").to_string()),
                Cell::new(if cred.auto_load { "Yes" } else { "No" }),
            ]));
        }
        
        table.printstd();
        return Ok(());
    }
    
    if args.remove {
        // Remove credential
        if let Some(key) = args.key {
            vm.remove_credential(&args.artifact_id, &key)?;
            println!("Credential '{}' removed successfully", key);
        } else {
            return Err(MicroVMError::ProcessError(
                "Key is required for credential removal".to_string()
            ));
        }
        return Ok(());
    }
    
    // Store new credential
    if let (Some(key), Some(value)) = (args.key, args.value) {
        vm.store_credential(&args.artifact_id, &key, &value, args.auto_load, args.description.as_deref())?;
        println!("Credential '{}' stored permanently with auto-load={}", key, args.auto_load);
    } else {
        return Err(MicroVMError::ProcessError(
            "Both key and value are required for storing credentials".to_string()
        ));
    }
    
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVarAccess {
    /// Environment variable patterns allowed (supports glob matching)
    pub allowed_vars: Vec<String>,
    /// Environment variable patterns explicitly denied
    pub denied_vars: Vec<String>,
    /// Environment variables to be injected
    pub injected_vars: HashMap<String, String>,
    /// Custom sanitization enabled
    pub enable_sanitization: bool,
    /// Audit environment access
    pub audit_env_access: bool,
}

// Updated ArtifactPermissions
pub struct ArtifactPermissions {
    // Existing fields
    pub can_write_fs: bool,
    pub can_access_network: bool,
    pub can_access_env: bool,
    pub allowed_paths: Vec<PathBuf>,
    pub executable_memory: bool,
    pub filesystem_mounts: Vec<FileSystemAccess>,
    // New enhanced env var management
    pub env_var_access: EnvVarAccess,
}

impl Default for EnvVarAccess {
    fn default() -> Self {
        Self {
            allowed_vars: vec!["PATH".to_string()], // Only PATH by default
            denied_vars: vec![
                "AWS_*".to_string(),
                "SECRET_*".to_string(),
                "PRIVATE_*".to_string(),
                "TOKEN_*".to_string(),
                "PASSWORD_*".to_string(),
                "CREDENTIALS_*".to_string(),
            ],
            injected_vars: HashMap::new(),
            enable_sanitization: true,
            audit_env_access: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialVault {
    /// Encrypted credential store
    encrypted_data: Vec<u8>,
    /// Metadata about stored credentials
    metadata: HashMap<String, CredentialMetadata>,
    /// Last modified timestamp
    last_modified: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Credential name/key
    name: String,
    /// Description (optional)
    description: Option<String>,
    /// When the credential was added
    added_at: chrono::DateTime<Utc>,
    /// Tags for organization
    tags: Vec<String>,
    /// Auto-load into environment flag
    auto_load: bool,
} 