use serde::{Serialize, Deserialize};
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;
use anyhow::{Context, Result};
use std::process::Command;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InstalledApp {
    pub name: String,
    pub publisher: String,
    pub install_location: String,
    pub display_version: String,
    pub icon_path: Option<String>,
    pub uninstall_string: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AppsResponse {
    pub apps: Vec<InstalledApp>,
}

/// Scan installed programs from Windows Registry
pub fn scan_installed_programs() -> Result<AppsResponse> {
    let mut apps = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // Scan both current user and all users installations
    // We scan current user first, then all users, to prioritize current user installations
    
    // First, scan current user installations (HKCU)
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let mut hkcu_count = 0;
    if let Ok(software) = hkcu.open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") {
        let before_count = apps.len();
        if let Err(e) = scan_uninstall_key(&software, &mut apps, &mut seen_names) {
            log::warn!("Failed to scan HKCU registry uninstall key: {}", e);
        } else {
            hkcu_count = apps.len() - before_count;
            log::info!("Found {} apps from HKCU registry", hkcu_count);
        }
    } else {
        log::warn!("Could not open HKCU Uninstall registry key");
    }

    // Then scan all users installations (HKLM) - but skip duplicates
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut hklm_count = 0;
    
    // 64-bit programs
    if let Ok(software) = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") {
        let before_count = apps.len();
        if let Err(e) = scan_uninstall_key_skip_duplicates(&software, &mut apps, &mut seen_names) {
            log::warn!("Failed to scan HKLM 64-bit registry uninstall key: {}", e);
        } else {
            hklm_count = apps.len() - before_count;
            log::info!("Found {} apps from HKLM 64-bit registry", hklm_count);
        }
    }
    
    // 32-bit programs (on 64-bit Windows)
    let mut hklm32_count = 0;
    if let Ok(software) = hklm.open_subkey("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall") {
        let before_count = apps.len();
        if let Err(e) = scan_uninstall_key_skip_duplicates(&software, &mut apps, &mut seen_names) {
            log::warn!("Failed to scan HKLM 32-bit registry uninstall key: {}", e);
        } else {
            hklm32_count = apps.len() - before_count;
            log::info!("Found {} apps from HKLM 32-bit registry", hklm32_count);
        }
    }
    
    let _registry_count = hkcu_count + hklm_count + hklm32_count;

    // Scan Start Menu shortcuts for additional programs (current user only)
    let mut start_menu_count = 0;
    let before_count = apps.len();
    if let Err(e) = scan_start_menu_programs(&mut apps, &mut seen_names) {
        log::warn!("Failed to scan Start Menu programs: {}", e);
    } else {
        start_menu_count = apps.len() - before_count;
        log::info!("Found {} apps from Start Menu", start_menu_count);
    }
    
    // Scan Desktop shortcuts for additional programs
    let mut desktop_count = 0;
    let before_count = apps.len();
    if let Err(e) = scan_desktop_programs(&mut apps, &mut seen_names) {
        log::warn!("Failed to scan Desktop programs: {}", e);
    } else {
        desktop_count = apps.len() - before_count;
        log::info!("Found {} apps from Desktop", desktop_count);
    }
    
    // Scan AppData folders for portable applications (reduced depth for speed)
    let mut appdata_count = 0;
    let before_count = apps.len();
    if let Err(e) = scan_appdata_programs(&mut apps, &mut seen_names) {
        log::warn!("Failed to scan AppData programs: {}", e);
    } else {
        appdata_count = apps.len() - before_count;
        log::info!("Found {} apps from AppData", appdata_count);
    }

    // Scan using PowerShell script for UWP, Chocolatey, Scoop, and system tools
    let mut powershell_count = 0;
    let before_count = apps.len();
    if let Err(e) = scan_powershell_apps(&mut apps, &mut seen_names) {
        log::warn!("Failed to scan PowerShell apps (UWP/Chocolatey/Scoop): {}", e);
    } else {
        powershell_count = apps.len() - before_count;
        log::info!("Found {} apps from PowerShell script (UWP/Chocolatey/Scoop/System)", powershell_count);
    }

    // Sort by name
    apps.sort_by(|a, b| a.name.cmp(&b.name));
    
    // Skip icon path post-processing to speed up scanning
    // Icons will be fetched on-demand by the client

    log::info!("Total apps found: {} (HKCU: {}, HKLM 64-bit: {}, HKLM 32-bit: {}, Start Menu: {}, Desktop: {}, AppData: {}, PowerShell: {})", 
               apps.len(), hkcu_count, hklm_count, hklm32_count, start_menu_count, desktop_count, appdata_count, powershell_count);

    Ok(AppsResponse { apps })
}

fn scan_uninstall_key(key: &RegKey, apps: &mut Vec<InstalledApp>, seen_names: &mut std::collections::HashSet<String>) -> Result<()> {
    for subkey_name in key.enum_keys().map(|x| x.unwrap()) {
        if let Ok(subkey) = key.open_subkey(&subkey_name) {
            if let Some(app) = extract_app_info(&subkey) {
                let app_key = format!("{}|{}", app.name.to_lowercase(), app.install_location.to_lowercase());
                if !seen_names.contains(&app_key) {
                    seen_names.insert(app_key);
                    apps.push(app);
                }
            }
        }
    }
    Ok(())
}

/// Scan uninstall key but skip apps that already exist (for HKLM after HKCU)
fn scan_uninstall_key_skip_duplicates(key: &RegKey, apps: &mut Vec<InstalledApp>, seen_names: &mut std::collections::HashSet<String>) -> Result<()> {
    for subkey_name in key.enum_keys().map(|x| x.unwrap()) {
        if let Ok(subkey) = key.open_subkey(&subkey_name) {
            if let Some(app) = extract_app_info(&subkey) {
                let app_key = format!("{}|{}", app.name.to_lowercase(), app.install_location.to_lowercase());
                if !seen_names.contains(&app_key) {
                    seen_names.insert(app_key);
                    apps.push(app);
                }
            }
        }
    }
    Ok(())
}

/// Scan Start Menu shortcuts for programs (using mitsuki user and all users)
fn scan_start_menu_programs(apps: &mut Vec<InstalledApp>, _seen_names: &mut std::collections::HashSet<String>) -> Result<()> {
    use std::path::Path;
    
    // Define the target username
    let target_user = "mitsuki";
    
    // Scan both target user and all users Start Menu
    let start_menu_paths = vec![
        // Target user's Start Menu
        format!(r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs", target_user),
        // All Users Start Menu
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs".to_string(),
    ];
    
    for start_menu_path in start_menu_paths {
        if !start_menu_path.is_empty() && Path::new(&start_menu_path).exists() {
            // Recursively scan for .lnk files - increased depth to 5 to catch more programs
            if let Err(e) = scan_start_menu_directory(&start_menu_path, apps, 0, 5) {
                log::warn!("Error scanning Start Menu directory {}: {}", start_menu_path, e);
            }
        }
    }
    
    Ok(())
}

/// Scan Desktop shortcuts for programs (mitsuki user and public desktop)
fn scan_desktop_programs(apps: &mut Vec<InstalledApp>, _seen_names: &mut std::collections::HashSet<String>) -> Result<()> {
    use std::path::Path;
    
    // Define the target username
    let target_user = "mitsuki";
    
    // Scan both target user and public desktop
    let desktop_paths = vec![
        // Target user's Desktop
        format!(r"C:\Users\{}\Desktop", target_user),
        // Public Desktop
        r"C:\Users\Public\Desktop".to_string(),
    ];
    
    for desktop_path in desktop_paths {
        if !desktop_path.is_empty() && Path::new(&desktop_path).exists() {
            // Scan for .lnk files on desktop (no recursion needed, desktop is flat)
            if let Err(e) = scan_desktop_directory(&desktop_path, apps) {
                log::warn!("Error scanning Desktop directory {}: {}", desktop_path, e);
            }
        }
    }
    
    Ok(())
}

/// Scan Desktop directory for shortcuts (non-recursive, desktop is typically flat)
fn scan_desktop_directory(dir_path: &str, apps: &mut Vec<InstalledApp>) -> Result<()> {
    let dir = match std::fs::read_dir(dir_path) {
        Ok(d) => d,
        Err(e) => {
            log::debug!("Cannot read Desktop directory {}: {}", dir_path, e);
            return Ok(());
        }
    };
    
    for entry in dir.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        
        // Only process .lnk files (shortcuts)
        if path_str.to_lowercase().ends_with(".lnk") {
            // Found a shortcut, extract program info
            if let Some(app) = extract_app_from_shortcut(&path_str) {
                // Avoid duplicates - check by name and install location
                // Desktop shortcuts are often duplicates of Start Menu, so be more permissive
                let is_duplicate = apps.iter().any(|a| {
                    // Check if we have the same executable path
                    if let (Some(ref a_icon), Some(ref app_icon)) = (a.icon_path.as_ref(), app.icon_path.as_ref()) {
                        let a_icon_lower = a_icon.replace('/', "\\").to_lowercase();
                        let app_icon_lower = app_icon.replace('/', "\\").to_lowercase();
                        if a_icon_lower == app_icon_lower {
                            return true;
                        }
                    }
                    // Also check by name and install location
                    a.name.to_lowercase() == app.name.to_lowercase() &&
                    a.install_location == app.install_location
                });
                
                if !is_duplicate {
                    log::debug!("Found Desktop app: {} at {}", app.name, path_str);
                    apps.push(app);
                } else {
                    // If duplicate found, prefer Desktop version if it has better icon info
                    if let Some(existing_idx) = apps.iter().position(|a| {
                        if let (Some(ref a_icon), Some(ref app_icon)) = (a.icon_path.as_ref(), app.icon_path.as_ref()) {
                            let a_icon_lower = a_icon.replace('/', "\\").to_lowercase();
                            let app_icon_lower = app_icon.replace('/', "\\").to_lowercase();
                            if a_icon_lower == app_icon_lower {
                                return true;
                            }
                        }
                        a.name.to_lowercase() == app.name.to_lowercase() &&
                        a.install_location == app.install_location
                    }) {
                        // Replace if Desktop version has icon and existing doesn't
                        if app.icon_path.is_some() && apps[existing_idx].icon_path.is_none() {
                            log::debug!("Replacing existing entry with Desktop app (better icon): {} at {}", app.name, path_str);
                            apps[existing_idx] = app;
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Scan AppData folders for portable applications
fn scan_appdata_programs(apps: &mut Vec<InstalledApp>, _seen_names: &mut std::collections::HashSet<String>) -> Result<()> {
    use std::path::Path;
    
    // Define the target username
    let target_user = "mitsuki";
    
    // AppData paths to scan - using the target user's profile
    let appdata_paths = vec![
        format!(r"C:\Users\{}\AppData\Local", target_user),
        format!(r"C:\Users\{}\AppData\Roaming", target_user),
        format!(r"C:\Users\{}\AppData\LocalLow", target_user),
    ];
    
    for appdata_path in &appdata_paths {
        if !Path::new(appdata_path).exists() {
            log::debug!("AppData path does not exist: {}", appdata_path);
            continue;
        }
        
        log::info!("Scanning AppData directory: {}", appdata_path);
        
        // Recursively scan for .exe files (increased depth to 8 for AppData to find apps in deeper structures)
        // Handle errors gracefully - continue with other paths if one fails
        if let Err(e) = scan_appdata_directory(appdata_path, apps, 0, 8) {
            log::warn!("Error scanning AppData directory {}: {}", appdata_path, e);
        }
    }
    
    Ok(())
}

/// Recursively scan AppData directory for executable files
fn scan_appdata_directory(dir_path: &str, apps: &mut Vec<InstalledApp>, current_depth: usize, max_depth: usize) -> Result<()> {
    // Limit recursion depth (increased for AppData to find apps in deeper structures)
    if current_depth >= max_depth {
        return Ok(());
    }
    
    let dir = match std::fs::read_dir(dir_path) {
        Ok(d) => d,
        Err(e) => {
            log::debug!("Cannot read AppData directory {}: {}", dir_path, e);
            return Ok(()); // Skip directories we can't read
        }
    };
    
    for entry in dir.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        
        if path.is_dir() {
            // Skip common system directories that shouldn't contain user apps
            let dir_name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();
            
            // Be more selective - only skip obvious system/temp directories
            // Don't skip "microsoft" or "packages" as they might contain user-installed apps
            // Only skip at top level (depth 0-1) to avoid filtering out app subdirectories
            if current_depth <= 1 {
                // Only skip obvious temp/cache/log directories at top level
                if dir_name == "temp" ||
                   dir_name == "cache" ||
                   dir_name == "crashdumps" ||
                   dir_name == "logs" ||
                   (dir_name.starts_with(".") && dir_name != ".local") {
                    log::debug!("Skipping system directory: {}", path_str);
                    continue;
                }
            }
            
            // Skip known system subdirectories at any depth (but be more selective)
            // Only skip if it's clearly a temp/cache/log directory
            if dir_name == "temp" || 
               dir_name == "cache" || 
               dir_name == "logs" ||
               dir_name == "crashdumps" ||
               dir_name == "tmp" {
                continue;
            }
            
            // Recursively search subdirectories - handle errors gracefully
            if let Err(e) = scan_appdata_directory(&path_str, apps, current_depth + 1, max_depth) {
                log::debug!("Error scanning AppData subdirectory {}: {}", path_str, e);
                // Continue with other entries
            }
        } else if path_str.to_lowercase().ends_with(".exe") {
            // Found an executable, extract program info
            if let Some(app) = extract_app_from_exe(&path_str) {
                // For AppData programs, check for duplicates by exact executable path
                // Normalize paths for comparison (handle case sensitivity and path separators)
                let normalized_exe_path = path_str.replace('/', "\\").to_lowercase();
                
                let is_duplicate = apps.iter().any(|a| {
                    // Check if icon_path matches (the exe path)
                    if let Some(ref icon_path) = a.icon_path {
                        let normalized_icon = icon_path.replace('/', "\\").to_lowercase();
                        if normalized_icon == normalized_exe_path {
                            return true;
                        }
                    }
                    // Also check if install_location + exe name matches
                    // This catches cases where Start Menu shortcuts point to the same exe
                    let exe_name = std::path::Path::new(&path_str)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.to_lowercase())
                        .unwrap_or_default();
                    if !exe_name.is_empty() {
                        let full_path_from_location = format!(r"{}\{}", 
                            a.install_location.replace('/', "\\").to_lowercase(), 
                            exe_name);
                        if full_path_from_location == normalized_exe_path {
                            return true;
                        }
                    }
                    false
                });
                
                if !is_duplicate {
                    log::debug!("Found AppData app: {} at {}", app.name, path_str);
                    apps.push(app);
                } else {
                    // If duplicate found, check if we should replace the existing entry
                    // Prefer AppData version if it has better information
                    if let Some(existing_idx) = apps.iter().position(|a| {
                        let normalized_exe_path = path_str.replace('/', "\\").to_lowercase();
                        if let Some(ref icon_path) = a.icon_path {
                            let normalized_icon = icon_path.replace('/', "\\").to_lowercase();
                            if normalized_icon == normalized_exe_path {
                                return true;
                            }
                        }
                        let exe_name = std::path::Path::new(&path_str)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.to_lowercase())
                            .unwrap_or_default();
                        if !exe_name.is_empty() {
                            let full_path_from_location = format!(r"{}\{}", 
                                a.install_location.replace('/', "\\").to_lowercase(), 
                                exe_name);
                            if full_path_from_location == normalized_exe_path {
                                return true;
                            }
                        }
                        false
                    }) {
                        // Replace if AppData version has better icon or if existing is from Start Menu
                        let existing_install_location = &apps[existing_idx].install_location;
                        let is_from_start_menu = existing_install_location.contains("Start Menu") || 
                                                 existing_install_location.contains("Programs");
                        if is_from_start_menu || (app.icon_path.is_some() && apps[existing_idx].icon_path.is_none()) {
                            log::debug!("Replacing existing entry with AppData app: {} at {}", app.name, path_str);
                            apps[existing_idx] = app;
                        } else {
                            log::debug!("Skipping duplicate AppData app: {} at {} (existing entry is better)", app.name, path_str);
                        }
                    } else {
                        log::debug!("Skipping duplicate AppData app: {} at {} (already exists)", app.name, path_str);
                    }
                }
            } else {
                log::debug!("Failed to extract app info from: {}", path_str);
            }
        }
    }
    
    Ok(())
}

/// Extract app information from an executable file
fn extract_app_from_exe(exe_path: &str) -> Option<InstalledApp> {
    use std::path::Path;
    
    // Check if file exists
    if !Path::new(exe_path).exists() {
        log::debug!("Executable does not exist: {}", exe_path);
        return None;
    }
    
    // Skip system executables (but be more specific - only skip if in Windows system directories)
    let exe_path_lower = exe_path.to_lowercase();
    if exe_path_lower.contains("\\windows\\system32\\") ||
       exe_path_lower.contains("\\windows\\syswow64\\") ||
       exe_path_lower.contains("\\windows\\temp\\") ||
       exe_path_lower.contains("\\windows\\cache\\") {
        log::debug!("Skipping system executable: {}", exe_path);
        return None;
    }
    
    // Get executable name
    let exe_name = Path::new(exe_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    
    if exe_name.is_empty() {
        log::debug!("Empty executable name for: {}", exe_path);
        return None;
    }
    
    // Skip uninstallers and system tools (but allow other executables)
    // Be more selective - only skip if it's clearly an uninstaller
    let exe_name_lower = exe_name.to_lowercase();
    if (exe_name_lower.contains("uninstall") && !exe_name_lower.contains("install")) ||
       exe_name_lower.contains("unins000") ||
       (exe_name_lower == "setup" && exe_path_lower.contains("temp")) {
        log::debug!("Skipping uninstaller/setup: {}", exe_path);
        return None;
    }
    
    // Try to get file description from executable
    let app_name = get_exe_file_description(exe_path)
        .unwrap_or_else(|| {
            // Fallback: use filename with spaces added
            add_spaces_to_camel_case(&exe_name)
        })
        .trim()
        .to_string();
    
    // If still empty after trimming, use the executable name as fallback
    // For AppData programs, we want to show them even with simple names
    let final_app_name = if app_name.is_empty() {
        // Use a more readable version of the exe name
        let readable_name = if exe_name.contains("Launcher") {
            // Extract app name from paths like "LineLauncher" -> "LINE"
            let parent_dir = Path::new(exe_path)
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .map(|s| s.to_uppercase())
                .unwrap_or_else(|| exe_name.clone());
            parent_dir
        } else {
            exe_name.clone()
        };
        readable_name
    } else {
        app_name
    };
    
    if final_app_name.is_empty() {
        log::warn!("Empty app name for: {}", exe_path);
        return None;
    }
    
    // Get install location (directory of executable)
    let install_location = Path::new(exe_path)
        .parent()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string())
        .unwrap_or_default();
    
    log::debug!("Extracted AppData app: {} from {}", final_app_name, exe_path);
    
    Some(InstalledApp {
        name: final_app_name,
        publisher: String::new(),
        install_location,
        display_version: String::new(),
        icon_path: Some(exe_path.to_string()),
        uninstall_string: None,
    })
}

/// Get file description from executable using PowerShell
fn get_exe_file_description(exe_path: &str) -> Option<String> {
    let ps_script = format!(
        r#"
        $exePath = '{}'
        try {{
            if (Test-Path $exePath) {{
                $fileInfo = Get-Item $exePath
                $desc = $fileInfo.VersionInfo.FileDescription
                if ($desc -and $desc.Trim()) {{
                    Write-Output $desc.Trim()
                }}
            }}
        }} catch {{
            Write-Output ""
        }}
        "#,
        exe_path.replace('\\', "\\\\").replace('\'', "\\'")
    );
    
    let output = std::process::Command::new("powershell")
        .args(&["-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .ok()?;
    
    if output.status.success() {
        let desc = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !desc.is_empty() {
            return Some(desc);
        }
    }
    
    None
}

/// Add spaces to CamelCase strings
fn add_spaces_to_camel_case(input: &str) -> String {
    if input.is_empty() || input.contains(' ') || input.len() < 3 {
        return input.to_string();
    }
    
    // Simple regex-like replacement: lowercase followed by uppercase
    let mut result = String::new();
    let chars: Vec<char> = input.chars().collect();
    
    for (i, &ch) in chars.iter().enumerate() {
        if i > 0 && ch.is_uppercase() && chars[i - 1].is_lowercase() {
            result.push(' ');
        }
        result.push(ch);
    }
    
    result
}

/// Recursively scan Start Menu directory for shortcuts
fn scan_start_menu_directory(dir_path: &str, apps: &mut Vec<InstalledApp>, current_depth: usize, max_depth: usize) -> Result<()> {
    // Limit recursion depth
    if current_depth >= max_depth {
        return Ok(());
    }
    
    let dir = match std::fs::read_dir(dir_path) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("Cannot read directory {}: {}", dir_path, e);
            return Ok(());
        }
    };
    
    for entry in dir.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        
        if path.is_dir() {
            // Recursively search subdirectories - handle errors gracefully
            if let Err(e) = scan_start_menu_directory(&path_str, apps, current_depth + 1, max_depth) {
                log::warn!("Error scanning subdirectory {}: {}", path_str, e);
                // Continue with other entries
            }
        } else if path_str.to_lowercase().ends_with(".lnk") {
            // Found a shortcut, extract program info
            if let Some(app) = extract_app_from_shortcut(&path_str) {
                // Avoid duplicates - only check by name (case-insensitive) to allow same app from different locations
                // This allows Start Menu shortcuts to show even if registry entry exists
                let is_duplicate = apps.iter().any(|a| {
                    a.name.to_lowercase() == app.name.to_lowercase()
                });
                
                if !is_duplicate {
                    apps.push(app);
                } else {
                    // If duplicate by name, prefer Start Menu version if it has better icon info
                    if let Some(existing_idx) = apps.iter().position(|a| a.name.to_lowercase() == app.name.to_lowercase()) {
                        // Replace if Start Menu version has icon and existing doesn't
                        if app.icon_path.is_some() && apps[existing_idx].icon_path.is_none() {
                            apps[existing_idx] = app;
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Extract app information from a .lnk shortcut file
fn extract_app_from_shortcut(lnk_path: &str) -> Option<InstalledApp> {
    use std::path::Path;
    
    // Get shortcut properties using PowerShell
    let ps_script = format!(
        r#"
        $lnkPath = '{}'
        try {{
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($lnkPath)
            
            $target = $shortcut.TargetPath
            $arguments = $shortcut.Arguments
            $workingDir = $shortcut.WorkingDirectory
            $iconLocation = $shortcut.IconLocation
            $description = $shortcut.Description
            
            # Skip uninstallers but allow system tools (they might be user-installed)
            if ($target -and $target -notlike '*uninstall*' -and $target -notlike '*unins000*') {{
                
                # Get name from shortcut file or target
                $lnkName = [System.IO.Path]::GetFileNameWithoutExtension($lnkPath)
                $targetName = if ($target) {{ [System.IO.Path]::GetFileNameWithoutExtension($target) }} else {{ $lnkName }}
                
                # Prefer description if available, otherwise use LNK name or target name
                $appName = if ($description -and $description.Trim()) {{ $description }} 
                          elseif ($lnkName -and $lnkName.Trim()) {{ $lnkName }}
                          else {{ $targetName }}
                
                # Get install location (directory of target or working directory)
                $installLocation = if ($target -and (Test-Path $target)) {{
                    [System.IO.Path]::GetDirectoryName($target)
                }} elseif ($workingDir -and (Test-Path $workingDir)) {{
                    $workingDir
                }} else {{
                    ""
                }}
                
                # Get icon path
                $iconPath = if ($iconLocation) {{
                    ($iconLocation -replace ',.*$', '').Trim()
                }} elseif ($target -and (Test-Path $target)) {{
                    $target
                }} else {{
                    ""
                }}
                
                # Output as JSON
                $result = @{{
                    name = $appName
                    publisher = ""
                    install_location = $installLocation
                    display_version = ""
                    icon_path = $iconPath
                    uninstall_string = ""
                }} | ConvertTo-Json -Compress
                
                Write-Output $result
            }}
        }} catch {{
            Write-Output ""
        }}
        "#,
        lnk_path.replace('\\', "\\\\").replace('\'', "\\'")
    );
    
    let output = std::process::Command::new("powershell")
        .args(&["-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .ok()?;
    
    if !output.status.success() {
        return None;
    }
    
    let json_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if json_str.is_empty() {
        return None;
    }
    
    // Parse JSON response
    let json: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    
    let name = json["name"].as_str()?.to_string();
    if name.is_empty() {
        return None;
    }
    
    // Skip system components
    if name.to_lowercase().contains("uninstall") || 
       name.to_lowercase().contains("remove") ||
       (name.to_lowercase().starts_with("microsoft ") && name.to_lowercase().contains("update")) {
        return None;
    }
    
    let install_location = json["install_location"].as_str().unwrap_or("").to_string();
    let icon_path = json["icon_path"].as_str().map(|s| s.to_string());
    
    // Get target from shortcut once (used for filtering and later processing)
    let target_opt = get_shortcut_target(lnk_path);
    
    // Filter out Windows administrative tools and system utilities
    // Check if target is in Windows system directories
    if let Some(ref target) = target_opt {
        let target_lower = target.to_lowercase();
        // Skip if target is in Windows system directories (unless it's a well-known user app)
        if target_lower.contains("\\windows\\system32\\") ||
           target_lower.contains("\\windows\\syswow64\\") ||
           target_lower.contains("\\windows\\system\\") {
            // Allow some exceptions for common user apps that might be in system32
            let allowed_in_system32 = vec![
                "notepad.exe",
                "calc.exe",
                "mspaint.exe",
                "cmd.exe",
                "powershell.exe",
            ];
            let is_allowed = allowed_in_system32.iter()
                .any(|&allowed| target_lower.ends_with(allowed));
            if !is_allowed {
                log::debug!("Skipping Windows system utility: {} -> {}", name, target);
                return None;
            }
        }
    }
    
    // Filter out Windows administrative tools by name patterns
    let name_lower = name.to_lowercase();
    let is_windows_admin_tool = name_lower.starts_with("capture") ||
        name_lower.starts_with("change settings") ||
        name_lower.starts_with("check your computer") ||
        name_lower.starts_with("configure policies") ||
        name_lower.starts_with("connect to remote") ||
        name_lower.starts_with("create a recovery") ||
        name_lower.starts_with("create and edit drawings") ||
        name_lower.starts_with("creates and edits text documents") ||
        name_lower.starts_with("diagnose performance") ||
        name_lower.starts_with("display detailed information") ||
        name_lower.starts_with("enables you to clear") ||
        name_lower.starts_with("maintains odbc") ||
        name_lower.starts_with("manage com+") ||
        name_lower.starts_with("manage running apps") ||
        name_lower.starts_with("manages disks") ||
        name_lower.contains("administrative tools") ||
        name_lower.contains("system tools") ||
        (name_lower.starts_with("windows ") && (
            name_lower.contains("memory diagnostic") ||
            name_lower.contains("disk cleanup") ||
            name_lower.contains("defragment") ||
            name_lower.contains("backup") ||
            name_lower.contains("restore") ||
            name_lower.contains("recovery") ||
            name_lower.contains("performance") ||
            name_lower.contains("monitor") ||
            name_lower.contains("resource") ||
            name_lower.contains("event viewer") ||
            name_lower.contains("task scheduler") ||
            name_lower.contains("services") ||
            name_lower.contains("device manager") ||
            name_lower.contains("computer management") ||
            name_lower.contains("disk management") ||
            name_lower.contains("group policy") ||
            name_lower.contains("local security") ||
            name_lower.contains("component services") ||
            name_lower.contains("iis manager") ||
            name_lower.contains("hyper-v") ||
            name_lower.contains("remote desktop") ||
            name_lower.contains("iscsi") ||
            name_lower.contains("odbc")
        ));
    
    if is_windows_admin_tool {
        log::debug!("Skipping Windows administrative tool: {}", name);
        return None;
    }
    
    // Try to get target from shortcut to verify/update install location
    if let Some(target) = target_opt {
        // Use target directory as install location if available
        let final_install_location = if Path::new(&target).exists() {
            Path::new(&target).parent()
                .and_then(|p| p.to_str())
                .map(|s| s.to_string())
                .unwrap_or(install_location)
        } else {
            // Even if target doesn't exist, use it as install location (might be network path, etc.)
            Path::new(&target).parent()
                .and_then(|p| p.to_str())
                .map(|s| s.to_string())
                .unwrap_or(install_location)
        };
        
        // Prefer target as icon path if icon_path is empty
        let final_icon_path = icon_path.or_else(|| {
            if Path::new(&target).exists() {
                Some(target.clone())
            } else {
                None
            }
        });
        
        return Some(InstalledApp {
            name,
            publisher: String::new(),
            install_location: final_install_location,
            display_version: String::new(),
            icon_path: final_icon_path,
            uninstall_string: None,
        });
    }
    
    // Fallback: use what we got from PowerShell
    Some(InstalledApp {
        name,
        publisher: String::new(),
        install_location,
        display_version: String::new(),
        icon_path,
        uninstall_string: None,
    })
}

fn extract_app_info(key: &RegKey) -> Option<InstalledApp> {
    // Get DisplayName - required field
    let name = key.get_value::<String, _>("DisplayName")
        .ok()?
        .trim()
        .to_string();
    
    // Skip if name is empty
    if name.is_empty() {
        return None;
    }
    
    // Skip system components and updates (optional filter)
    if name.contains("Update for") || 
       name.contains("Security Update") ||
       name.contains("Hotfix") ||
       (name.starts_with("Microsoft ") && name.contains("Update")) {
        return None;
    }
    
    // Skip uninstallers and maintenance tools
    let name_lower = name.to_lowercase();
    if name_lower.contains("uninstall") ||
       name_lower.contains("maintenance service") ||
       name_lower.ends_with(" uninstaller") {
        return None;
    }

    let publisher = key.get_value::<String, _>("Publisher")
        .unwrap_or_default()
        .trim()
        .to_string();

    let display_version = key.get_value::<String, _>("DisplayVersion")
        .unwrap_or_default()
        .trim()
        .to_string();

    // Get UninstallString first (needed for fallback)
    let uninstall_string = key.get_value::<String, _>("UninstallString")
        .ok()
        .map(|s| s.trim().to_string());

    // Get InstallLocation
    let mut install_location = key.get_value::<String, _>("InstallLocation")
        .unwrap_or_else(|_| {
            // Fallback: try to extract from UninstallString
            uninstall_string.as_ref()
                .map(|s| s.as_str())
                .unwrap_or("")
                .to_string()
        })
        .trim()
        .to_string();

    // Clean up install location (remove quotes and uninstaller paths)
    install_location = clean_install_location(&install_location);
    
    // If install location is still empty or invalid, try to extract from uninstall string
    if install_location.is_empty() || !std::path::Path::new(&install_location).exists() {
        if let Some(ref uninstall) = uninstall_string {
            let cleaned = clean_install_location(uninstall);
            if !cleaned.is_empty() && std::path::Path::new(&cleaned).exists() {
                install_location = cleaned;
            }
        }
    }
    
    // Skip if install location points to an uninstaller
    let install_location_lower = install_location.to_lowercase();
    if install_location_lower.contains("uninstall") ||
       install_location_lower.contains("maintenance service") ||
       install_location_lower.ends_with("uninstall.exe") ||
       install_location_lower.ends_with("unins000.exe") {
        return None;
    }

    // Try to find icon
    let icon_path = find_icon(&name, &install_location, key);

    Some(InstalledApp {
        name,
        publisher,
        install_location,
        display_version,
        icon_path,
        uninstall_string,
    })
}

fn clean_install_location(location: &str) -> String {
    let mut cleaned = location.trim().to_string();
    
    // Remove quotes
    if cleaned.starts_with('"') && cleaned.ends_with('"') {
        cleaned = cleaned[1..cleaned.len()-1].to_string();
    }
    
    // Remove common uninstaller names
    let uninstallers = [
        "uninstall.exe",
        "Uninstall.exe",
        "UNINSTALL.EXE",
        "unins000.exe",
        "Unins000.exe",
    ];
    
    for uninstaller in &uninstallers {
        if cleaned.to_lowercase().ends_with(&uninstaller.to_lowercase()) {
            if let Some(parent) = PathBuf::from(&cleaned).parent() {
                cleaned = parent.to_string_lossy().to_string();
            }
        }
    }
    
    cleaned
}

fn find_icon(name: &str, install_location: &str, key: &RegKey) -> Option<String> {
    // First, try DisplayIcon from registry
    if let Ok(icon) = key.get_value::<String, _>("DisplayIcon") {
        let icon_path = icon.split(',').next().unwrap_or(&icon).trim();
        if !icon_path.is_empty() && std::path::Path::new(icon_path).exists() {
            return Some(icon_path.to_string());
        }
    }

    // Try to find icon from Start Menu shortcuts
    if let Some(start_menu_icon) = find_icon_from_start_menu(name) {
        return Some(start_menu_icon);
    }

    // If install location exists, look for exe files
    if !install_location.is_empty() && std::path::Path::new(&install_location).exists() {
        let dir = std::fs::read_dir(&install_location).ok()?;
        
        // Look for exe files that might match the app name
        let name_lower = name.to_lowercase();
        let search_terms: Vec<String> = name_lower
            .split_whitespace()
            .take(2)
            .map(|s| s.to_string())
            .collect();
        
        for entry in dir.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() {
                    let file_name = entry.file_name();
                    let file_name_str = file_name.to_string_lossy().to_lowercase();
                    
                    if file_name_str.ends_with(".exe") {
                        // Check if filename contains app name keywords
                        let matches = search_terms.iter()
                            .any(|term| file_name_str.contains(term));
                        
                        if matches || file_name_str == format!("{}.exe", name_lower.replace(' ', "")) {
                            let full_path = entry.path().to_string_lossy().to_string();
                            if std::path::Path::new(&full_path).exists() {
                                return Some(full_path);
                            }
                        }
                    }
                }
            }
        }
        
        // Fallback: find first exe in directory
        let dir = std::fs::read_dir(&install_location).ok()?;
        for entry in dir.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() {
                    let file_name = entry.file_name();
                    let file_name_str = file_name.to_string_lossy();
                    
                    if file_name_str.to_lowercase().ends_with(".exe") {
                        let full_path = entry.path().to_string_lossy().to_string();
                        if std::path::Path::new(&full_path).exists() {
                            return Some(full_path);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Find icon from Start Menu shortcuts
fn find_icon_from_start_menu(app_name: &str) -> Option<String> {
    use std::path::Path;
    
    // Scan both current user and all users Start Menu
    let start_menu_paths = vec![
        // Current User Start Menu
        std::env::var("APPDATA")
            .map(|appdata| format!(r"{}\Microsoft\Windows\Start Menu\Programs", appdata))
            .unwrap_or_else(|_| {
                // Fallback to USERPROFILE
                std::env::var("USERPROFILE")
                    .map(|profile| format!(r"{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs", profile))
                    .unwrap_or_default()
            }),
        // All Users Start Menu
        std::env::var("ProgramData")
            .map(|programdata| format!(r"{}\Microsoft\Windows\Start Menu\Programs", programdata))
            .unwrap_or_else(|_| r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs".to_string()),
    ];
    
    let app_name_lower = app_name.to_lowercase();
    let search_terms: Vec<String> = app_name_lower
        .split_whitespace()
        .take(3)
        .map(|s| s.to_string())
        .collect();
    
    for start_menu_path in start_menu_paths {
        if !Path::new(&start_menu_path).exists() {
            continue;
        }
        
        // Recursively search for .lnk files (max depth 3 to avoid scanning too deep)
        if let Some(icon_path) = search_start_menu_recursive(&start_menu_path, &app_name_lower, &search_terms, 0, 3) {
            return Some(icon_path);
        }
    }
    
    None
}

/// Recursively search Start Menu for matching shortcuts
fn search_start_menu_recursive(dir_path: &str, app_name: &str, search_terms: &[String], current_depth: usize, max_depth: usize) -> Option<String> {
    use std::path::Path;
    
    // Limit recursion depth
    if current_depth >= max_depth {
        return None;
    }
    
    let dir = std::fs::read_dir(dir_path).ok()?;
    
    for entry in dir.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        
        if path.is_dir() {
            // Recursively search subdirectories
            if let Some(icon) = search_start_menu_recursive(&path_str, app_name, search_terms, current_depth + 1, max_depth) {
                return Some(icon);
            }
        } else if path_str.to_lowercase().ends_with(".lnk") {
            // Found a shortcut, check if it matches the app name
            let file_name = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            
            // Check if shortcut name matches app name
            // More flexible matching: check if any search term is in filename
            // or if filename is similar to app name
            let matches = if search_terms.is_empty() {
                false
            } else {
                search_terms.iter()
                    .any(|term| file_name.contains(term)) || 
                    file_name.contains(app_name) ||
                    // Check if first word of app name matches
                    (app_name.len() > 3 && file_name.starts_with(&app_name[..app_name.len().min(5)]))
            };
            
            if matches {
                // First, try to get icon directly from shortcut
                if let Some(icon_path) = get_shortcut_icon(&path_str) {
                    if Path::new(&icon_path).exists() {
                        return Some(icon_path);
                    }
                }
                
                // Fallback: get target path from .lnk file using PowerShell
                if let Some(target_path) = get_shortcut_target(&path_str) {
                    if Path::new(&target_path).exists() {
                        return Some(target_path);
                    }
                }
            }
        }
    }
    
    None
}

/// Find icon from Desktop shortcuts
fn find_icon_from_desktop(app_name: &str) -> Option<String> {
    use std::path::Path;
    
    // Scan both current user and public desktop
    let desktop_paths = vec![
        // Current User Desktop
        std::env::var("USERPROFILE")
            .map(|profile| format!(r"{}\Desktop", profile))
            .unwrap_or_default(),
        // Public Desktop
        std::env::var("PUBLIC")
            .map(|public| format!(r"{}\Desktop", public))
            .unwrap_or_else(|_| r"C:\Users\Public\Desktop".to_string()),
    ];
    
    let app_name_lower = app_name.to_lowercase();
    let search_terms: Vec<String> = app_name_lower
        .split_whitespace()
        .take(3)
        .map(|s| s.to_string())
        .collect();
    
    for desktop_path in desktop_paths {
        if !Path::new(&desktop_path).exists() {
            continue;
        }
        
        // Search for .lnk files on desktop
        if let Some(icon_path) = search_desktop_recursive(&desktop_path, &app_name_lower, &search_terms) {
            return Some(icon_path);
        }
    }
    
    None
}

/// Search Desktop for matching shortcuts (non-recursive, desktop is typically flat)
fn search_desktop_recursive(dir_path: &str, app_name: &str, search_terms: &[String]) -> Option<String> {
    use std::path::Path;
    
    let dir = std::fs::read_dir(dir_path).ok()?;
    
    for entry in dir.flatten() {
        let path = entry.path();
        let path_str = path.to_string_lossy().to_string();
        
        if path_str.to_lowercase().ends_with(".lnk") {
            // Found a shortcut, check if it matches the app name
            let file_name = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            
            // Check if shortcut name matches app name
            let matches = if search_terms.is_empty() {
                false
            } else {
                search_terms.iter()
                    .any(|term| file_name.contains(term)) || 
                    file_name.contains(app_name) ||
                    (app_name.len() > 3 && file_name.starts_with(&app_name[..app_name.len().min(5)]))
            };
            
            if matches {
                // First, try to get icon directly from shortcut
                if let Some(icon_path) = get_shortcut_icon(&path_str) {
                    if Path::new(&icon_path).exists() {
                        return Some(icon_path);
                    }
                }
                
                // Fallback: get target path from .lnk file
                if let Some(target_path) = get_shortcut_target(&path_str) {
                    if Path::new(&target_path).exists() {
                        return Some(target_path);
                    }
                }
            }
        }
    }
    
    None
}

/// Get icon path directly from a .lnk shortcut file using PowerShell
fn get_shortcut_icon(lnk_path: &str) -> Option<String> {
    use std::process::Command;
    
    let ps_script = format!(
        r#"
        $lnkPath = '{}'
        try {{
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($lnkPath)
            $iconLocation = $shortcut.IconLocation
            if ($iconLocation) {{
                $iconPath = $iconLocation -replace ',.*$', ''
                if ($iconPath -and (Test-Path $iconPath)) {{
                    Write-Output $iconPath
                }}
            }}
        }} catch {{
            Write-Output ""
        }}
        "#,
        lnk_path.replace('\\', "\\\\").replace('\'', "\\'")
    );
    
    let output = Command::new("powershell")
        .args(&["-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .ok()?;
    
    if output.status.success() {
        let icon_path = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string();
        if !icon_path.is_empty() {
            return Some(icon_path);
        }
    }
    
    None
}

/// Get target path from a .lnk shortcut file using PowerShell
fn get_shortcut_target(lnk_path: &str) -> Option<String> {
    use std::process::Command;
    
    let ps_script = format!(
        r#"
        $lnkPath = '{}'
        try {{
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($lnkPath)
            $target = $shortcut.TargetPath
            if ($target) {{
                Write-Output $target
            }}
        }} catch {{
            Write-Output ""
        }}
        "#,
        lnk_path.replace('\\', "\\\\").replace('\'', "\\'")
    );
    
    let output = Command::new("powershell")
        .args(&["-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .ok()?;
    
    if output.status.success() {
        let target = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string();
        if !target.is_empty() {
            return Some(target);
        }
    }
    
    None
}

/// Extract icon from executable and return as base64
pub fn extract_icon_base64(exe_path: &str) -> Result<String> {
    use std::process::Command;
    use std::path::Path;
    
    // Check if file exists first
    if !Path::new(exe_path).exists() {
        return Err(anyhow::anyhow!("File does not exist: {}", exe_path));
    }
    
    // Skip uninstallers
    let exe_path_lower = exe_path.to_lowercase();
    if exe_path_lower.contains("uninstall") || 
       exe_path_lower.contains("unins000") ||
       exe_path_lower.ends_with("uninstall.exe") {
        return Err(anyhow::anyhow!("Skipping uninstaller: {}", exe_path));
    }
    
    // Use PowerShell to extract icon (improved error handling)
    let ps_script = format!(
        r#"
        $exePath = '{}'
        try {{
            if (-not (Test-Path $exePath)) {{
                Write-Error "File not found: $exePath"
                exit 1
            }}
            
            Add-Type -AssemblyName System.Drawing -ErrorAction Stop
            $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($exePath)
            if ($null -eq $icon) {{
                Write-Error "Failed to extract icon"
                exit 1
            }}
            
            $bitmap = $icon.ToBitmap()
            $ms = New-Object System.IO.MemoryStream
            $bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
            $bytes = $ms.ToArray()
            $ms.Close()
            $bitmap.Dispose()
            $icon.Dispose()
            
            [Convert]::ToBase64String($bytes)
        }} catch {{
            Write-Error $_.Exception.Message
            exit 1
        }}
        "#,
        exe_path.replace('\\', "\\\\").replace('\'', "\\'")
    );

    let output = Command::new("powershell")
        .args(&[
            "-ExecutionPolicy",
            "Bypass",
            "-NoProfile",
            "-Command",
            &ps_script,
        ])
        .output()
        .context("Failed to execute PowerShell")?;

    if output.status.success() {
        let base64 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string();
        if !base64.is_empty() && !base64.starts_with("Error") {
            return Ok(base64);
        }
    }
    
    // Log the error for debugging
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    log::warn!("Icon extraction failed for {}: stdout={}, stderr={}", exe_path, stdout, stderr);

    Err(anyhow::anyhow!("Failed to extract icon from {}", exe_path))
}

/// PowerShell script output structure
#[derive(Deserialize, Debug)]
struct PowerShellApp {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Args")]
    args: Option<String>,
    #[serde(rename = "Icon")]
    icon: Option<String>,
    #[serde(rename = "Source")]
    source: String,
}

/// Scan apps using PowerShell script (UWP, Chocolatey, Scoop, System Tools)
fn scan_powershell_apps(apps: &mut Vec<InstalledApp>, _seen_names: &mut std::collections::HashSet<String>) -> Result<()> {
    // Try to find the PowerShell script
    let script_path = find_powershell_script()?;
    
    log::debug!("Using PowerShell script at: {}", script_path);
    
    // Execute PowerShell script
    let output = Command::new("powershell")
        .args(&[
            "-ExecutionPolicy",
            "Bypass",
            "-NoProfile",
            "-Command",
            &format!(
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & '{}'",
                script_path.replace('\\', "\\\\").replace('\'', "\\'")
            ),
        ])
        .output()
        .context("Failed to execute PowerShell script")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("PowerShell script failed: {}", stderr);
        return Err(anyhow::anyhow!("PowerShell script execution failed: {}", stderr));
    }

    // Parse JSON output
    let json_str = String::from_utf8_lossy(&output.stdout);
    let json_str = json_str.trim();
    
    if json_str.is_empty() {
        log::warn!("PowerShell script returned empty output");
        return Ok(());
    }

    // Parse JSON array
    let ps_apps: Vec<PowerShellApp> = serde_json::from_str(json_str)
        .context("Failed to parse PowerShell script JSON output")?;

    log::debug!("Parsed {} apps from PowerShell script", ps_apps.len());

    // Convert and merge PowerShell apps
    for ps_app in ps_apps {
        // Skip if already exists (by name, case-insensitive, or by path)
        let is_duplicate = apps.iter().any(|a| {
            a.name.to_lowercase() == ps_app.name.to_lowercase() ||
            a.install_location.to_lowercase() == ps_app.path.to_lowercase()
        });

        if is_duplicate {
            continue;
        }

        // Convert PowerShell app to InstalledApp
        let install_location = if ps_app.source == "uwp" {
            // For UWP, use the launch args as install location
            ps_app.args.as_ref()
                .map(|s| s.clone())
                .unwrap_or_default()
        } else if ps_app.path.ends_with(".exe") {
            // For regular executables, store the full path (not just directory)
            // This makes it easier to launch the app
            ps_app.path.clone()
        } else {
            // Get directory from path for non-exe files
            PathBuf::from(&ps_app.path)
                .parent()
                .and_then(|p| p.to_str())
                .map(|s| s.to_string())
                .unwrap_or_default()
        };

        let icon_path = if let Some(icon) = &ps_app.icon {
            // If icon is base64, we need to handle it differently
            // For now, if it's a path, use it; if it's base64, we'll need to extract from path
            if icon.starts_with("data:") || icon.len() > 200 {
                // Likely base64, try to get icon from path instead
                if ps_app.path.ends_with(".exe") {
                    Some(ps_app.path.clone())
                } else {
                    None
                }
            } else if std::path::Path::new(icon).exists() {
                Some(icon.clone())
            } else if ps_app.path.ends_with(".exe") {
                Some(ps_app.path.clone())
            } else {
                None
            }
        } else if ps_app.path.ends_with(".exe") {
            Some(ps_app.path.clone())
        } else {
            None
        };

        let app = InstalledApp {
            name: ps_app.name,
            publisher: String::new(),
            install_location,
            display_version: String::new(),
            icon_path,
            uninstall_string: None,
        };

        apps.push(app);
    }

    Ok(())
}

/// Find the PowerShell script path
fn find_powershell_script() -> Result<String> {
    use std::path::Path;
    
    // Try multiple possible locations
    let mut possible_paths = Vec::new();
    
    // Relative paths
    possible_paths.push("scripts\\apps.ps1".to_string());
    possible_paths.push("syscore\\servergo\\scripts\\apps.ps1".to_string());
    
    // From current directory
    if let Ok(current_dir) = std::env::current_dir() {
        let path = current_dir.join("syscore").join("servergo").join("scripts").join("apps.ps1");
        possible_paths.push(path.to_string_lossy().to_string());
    }
    
    // From executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // Try scripts subdirectory
            let path = exe_dir.join("scripts").join("apps.ps1");
            possible_paths.push(path.to_string_lossy().to_string());
            
            // Try going up to find syscore
            if let Some(parent) = exe_dir.parent() {
                let path = parent.join("syscore").join("servergo").join("scripts").join("apps.ps1");
                possible_paths.push(path.to_string_lossy().to_string());
            }
        }
    }

    for path in &possible_paths {
        if Path::new(path).exists() {
            log::debug!("Found PowerShell script at: {}", path);
            return Ok(path.clone());
        }
    }

    Err(anyhow::anyhow!("PowerShell script apps.ps1 not found. Searched in: {}", possible_paths.join(", ")))
}

