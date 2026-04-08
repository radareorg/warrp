use std::ffi::CString;
use std::path::Path;

use crate::r2::ffi::{RCore, r_cons_print, r_core_cmd_str, free};
use crate::r2::analysis;
use crate::r2::guid::compute_function_guid;
use crate::warp::container::WarpContainer;

pub unsafe fn handle_zw_command(
    core: *mut RCore,
    container: &mut WarpContainer,
    input: &str,
) -> bool {
    // Strip "zw" prefix to get subcommand part
    let rest = input.strip_prefix("zw").unwrap_or("");

    // Check for help: "zw?" or "zw ?" or "zw??"
    if rest.starts_with('?') || rest.trim().starts_with('?') {
        return cmd_help(core);
    }

    let args: Vec<&str> = input.split_whitespace().collect();
    let subcmd = args.get(1).copied().unwrap_or("");
    let subargs: &[&str] = if args.len() > 2 { &args[2..] } else { &[] };

    match subcmd {
        "" | "list" | "l" => cmd_list(core, container),
        "load" => cmd_load(core, container, subargs),
        "save" => cmd_save(core, container, subargs),
        "match" => cmd_match(core, container, subargs),
        "create" => cmd_create(core, container, subargs),
        "info" => cmd_info(core, container),
        "clear" => cmd_clear(core, container),
        "test" => cmd_test(core, container, subargs),
        "?" | "help" => cmd_help(core),
        _ => {
            show_error(core, &format!("Unknown command: zw {}", subcmd));
            cmd_help(core);
            true
        }
    }
}

unsafe fn cmd_help(core: *mut RCore) -> bool {
    let help = concat!(
        "Usage: zw  # Manage WARP signatures\n",
        "zw                list loaded WARP containers\n",
        "zw?               show this help\n",
        "zw load <file>    load WARP signature file (.warp)\n",
        "zw save <file>    save current signatures to WARP file\n",
        "zw match [addr]   match function at address\n",
        "zw match -a       match all functions in binary\n",
        "zw create [addr]  create WARP signature for function\n",
        "zw create -a      create signatures for all functions\n",
        "zw test <binary>  test GUID generation against snapshot\n",
        "zw info           show container/target info\n",
        "zw clear          clear loaded containers\n",
    );
    print_str(core, help);
    true
}

unsafe fn cmd_list(core: *mut RCore, container: &WarpContainer) -> bool {
    print_str(core, "Loaded WARP containers:\n");

    let files = container.list_files();
    if files.is_empty() {
        print_str(core, "  (none)\n");
    } else {
        for (i, file) in files.iter().enumerate() {
            print_str(core, &format!("  {}. {}\n", i + 1, file));
        }
    }

    if let Some(ref target) = container.get_target() {
        print_str(core, &format!(
            "Target: {} / {}\n",
            target.architecture,
            target.platform
        ));
    }

    print_str(core, &format!("Functions loaded: {}\n", container.function_count()));
    true
}

unsafe fn cmd_load(
    core: *mut RCore,
    container: &mut WarpContainer,
    args: &[&str],
) -> bool {
    let path = match args.get(0) {
        Some(p) => *p,
        None => {
            show_error(core, "Usage: zw load <file.warp>");
            return true;
        }
    };

    print_str(core, &format!("Loading WARP file: {}\n", path));

    match container.load(Path::new(path)) {
        Ok(()) => {
            print_str(core, "Successfully loaded WARP file\n");
            print_str(core, &format!("Functions loaded: {}\n", container.function_count()));
            true
        }
        Err(e) => {
            show_error(core, &format!("Failed to load WARP file: {}", e));
            true
        }
    }
}

unsafe fn cmd_save(
    core: *mut RCore,
    container: &mut WarpContainer,
    args: &[&str],
) -> bool {
    let path = match args.get(0) {
        Some(p) => *p,
        None => {
            show_error(core, "Usage: zw save <file.warp>");
            return true;
        }
    };

    print_str(core, &format!("Saving WARP file: {}\n", path));

    match container.save(Path::new(path)) {
        Ok(()) => {
            print_str(core, "Successfully saved WARP file\n");
            true
        }
        Err(e) => {
            show_error(core, &format!("Failed to save WARP file: {}", e));
            true
        }
    }
}

unsafe fn cmd_match(
    core: *mut RCore,
    container: &mut WarpContainer,
    args: &[&str],
) -> bool {
    if container.function_count() == 0 {
        show_error(core, "No WARP signatures loaded. Use 'zw load' first.");
        return true;
    }

    if !analysis::ensure_functions_exist(core) {
        show_error(core, "No functions found after analysis. Binary may be unsupported.");
        return true;
    }

    let match_all = args.contains(&"-a");

    if match_all {
        cmd_match_all(core, container)
    } else {
        let addr_str = args.iter()
            .find(|a| !a.starts_with('-'))
            .copied()
            .unwrap_or("$$");

        let addr = parse_address(core, addr_str);
        if addr == 0 {
            show_error(core, "Invalid address");
            return true;
        }

        cmd_match_single(core, container, addr)
    }
}

unsafe fn cmd_match_all(core: *mut RCore, container: &WarpContainer) -> bool {
    print_str(core, "Matching all functions against WARP signatures...\n");

    let functions = analysis::get_all_functions(core);
    if functions.is_empty() {
        show_error(core, "No functions found in current binary.");
        return true;
    }

    let regions = analysis::get_relocatable_regions(core);

    let mut matched = 0u64;
    let mut unmatched = 0u64;
    let mut ambiguous = 0u64;

    for fcn_addr in &functions {
        match container.match_with_constraints(core, *fcn_addr, &regions) {
            Some(candidates) => {
                if let Some((best, _score)) = candidates.first() {
                    analysis::apply_function_metadata(core, *fcn_addr, best);
                    let extra = if candidates.len() > 1 {
                        format!(" ({} candidates)", candidates.len())
                    } else {
                        String::new()
                    };
                    print_str(core, &format!(
                        "0x{:08x}: {} -> {}{}\n",
                        fcn_addr,
                        best.guid,
                        best.symbol.name,
                        extra
                    ));
                    matched += 1;
                    if candidates.len() > 1 {
                        ambiguous += 1;
                    }
                } else {
                    unmatched += 1;
                }
            }
            None => {
                match compute_function_guid(core, *fcn_addr, &regions, None) {
                    Ok(guid) => {
                        if let Some(matches) = container.find_by_guid(&guid) {
                            if !matches.is_empty() {
                                let name = &matches[0].symbol.name;
                                analysis::apply_function_metadata(core, *fcn_addr, &matches[0]);
                                print_str(core, &format!(
                                    "0x{:08x}: {} -> {}\n",
                                    fcn_addr,
                                    guid,
                                    name
                                ));
                                matched += 1;
                            } else {
                                unmatched += 1;
                            }
                        } else {
                            unmatched += 1;
                        }
                    }
                    Err(_) => {
                        unmatched += 1;
                    }
                }
            }
        }
    }

    print_str(core, &format!(
        "Matched: {} / {} (ambiguous: {})\n",
        matched,
        matched + unmatched,
        ambiguous
    ));

    true
}

unsafe fn cmd_match_single(
    core: *mut RCore,
    container: &WarpContainer,
    addr: u64,
) -> bool {
    print_str(core, &format!("Matching function at 0x{:08x}...\n", addr));

    let regions = analysis::get_relocatable_regions(core);

    // Try constraint-based matching first
    match container.match_with_constraints(core, addr, &regions) {
        Some(candidates) => {
            print_str(core, &format!("Found {} candidate(s) by GUID:\n", candidates.len()));

            for (i, (func, _score)) in candidates.iter().enumerate() {
                let marker = if i == 0 { "*" } else { " " };
                print_str(core, &format!(
                    "  {}{}. {} ({} constraints)\n",
                    marker,
                    i + 1,
                    func.symbol.name,
                    func.constraints.len()
                ));
            }

            // Apply best match
            if let Some((best, _score)) = candidates.first() {
                analysis::apply_function_metadata(core, addr, best);
                print_str(core, &format!("Applied: {}\n", best.symbol.name));
            }
            return true;
        }
        None => {}
    }

    // Fallback to GUID-only matching
    let guid = match compute_function_guid(core, addr, &regions, None) {
        Ok(g) => g,
        Err(e) => {
            show_error(core, &format!("Failed to compute function GUID: {}", e));
            return true;
        }
    };

    print_str(core, &format!("Function GUID: {} (no constraint matches)\n", guid));

    match container.find_by_guid(&guid) {
        Some(matches) if !matches.is_empty() => {
            print_str(core, &format!("Found {} match(es):\n", matches.len()));
            for (i, func) in matches.iter().enumerate() {
                print_str(core, &format!(
                    "  {}. {} (constraints: {})\n",
                    i + 1,
                    func.symbol.name,
                    func.constraints.len()
                ));
            }

            if matches.len() == 1 {
                let name = &matches[0].symbol.name;
                analysis::apply_function_metadata(core, addr, &matches[0]);
                print_str(core, &format!("Applied: {}\n", name));
            } else {
                print_str(core, "Multiple matches found. Use constraints to disambiguate.\n");
            }
            true
        }
        Some(_) | None => {
            show_error(core, "No matching function found in WARP signatures.");
            true
        }
    }
}

unsafe fn cmd_create(
    core: *mut RCore,
    container: &mut WarpContainer,
    args: &[&str],
) -> bool {
    let create_all = args.contains(&"-a");

    if create_all {
        cmd_create_all(core, container)
    } else {
        let addr_str = args.iter()
            .find(|a| !a.starts_with('-'))
            .copied()
            .unwrap_or("$$");

        let addr = parse_address(core, addr_str);
        if addr == 0 {
            show_error(core, "Invalid address");
            return true;
        }

        cmd_create_single(core, container, addr)
    }
}

unsafe fn cmd_create_all(core: *mut RCore, container: &mut WarpContainer) -> bool {
    if !analysis::ensure_functions_exist(core) {
        show_error(core, "No functions found after analysis. Binary may be unsupported.");
        return true;
    }

    let interactive = analysis::is_interactive(core);

    if interactive {
        print_str(core, "Initializing analysis cache...");
        crate::r2::ffi::r_cons_flush(
            crate::r2::ffi::r_core_get_cons(core)
        );
    }

    container.initialize_cache(core);

    let functions = container.cache.get_all_functions().to_vec();
    let total = functions.len();

    if total == 0 {
        show_error(core, "No functions found in current binary.");
        return true;
    }

    if interactive {
        print_str(core, &format!("\rCreating WARP signatures for {} functions...\n", total));
    } else {
        print_str(core, &format!("Creating WARP signatures for {} functions...\n", total));
    }

    for (i, fcn_addr) in functions.iter().enumerate() {
        if interactive {
            print_str(core, &format!("\rProcessing {}/{}...", i + 1, total));
            crate::r2::ffi::r_cons_flush(
                crate::r2::ffi::r_core_get_cons(core)
            );
        }

        if let Err(e) = container.add_function_from_binary(core, *fcn_addr) {
            if interactive {
                print_str(core, &format!(
                    "\nWarning: Failed to add function at 0x{:x}: {}\n",
                    fcn_addr, e
                ));
            }
        }
    }

    if interactive {
        print_str(core, "\n");
    } else {
        print_str(core, &format!("Created signatures for {} functions\n", total));
    }

    true
}

unsafe fn cmd_create_single(
    core: *mut RCore,
    container: &mut WarpContainer,
    addr: u64,
) -> bool {
    container.initialize_cache(core);

    match container.add_function_from_binary(core, addr) {
        Ok(guid) => {
            print_str(core, &format!("Created signature: {}\n", guid));
            true
        }
        Err(e) => {
            show_error(core, &format!("Failed to create signature: {}", e));
            true
        }
    }
}

unsafe fn cmd_info(core: *mut RCore, container: &WarpContainer) -> bool {
    print_str(core, "WARP Container Information:\n");
    print_str(core, &format!("Files loaded: {}\n", container.file_count()));
    print_str(core, &format!("Functions: {}\n", container.function_count()));

    if let Some(ref target) = container.get_target() {
        print_str(core, &format!("Architecture: {}\n", target.architecture));
        print_str(core, &format!("Platform: {}\n", target.platform));
    }

    true
}

unsafe fn cmd_clear(core: *mut RCore, container: &mut WarpContainer) -> bool {
    container.clear();
    print_str(core, "Cleared all loaded WARP signatures.\n");
    true
}

unsafe fn cmd_test(
    core: *mut RCore,
    container: &mut WarpContainer,
    args: &[&str],
) -> bool {
    let binary_path = match args.get(0) {
        Some(p) => *p,
        None => {
            show_error(core, "Usage: zw test <binary>");
            return true;
        }
    };

    let snap_path = match args.get(1) {
        Some(p) => *p,
        None => {
            show_error(core, "Usage: zw test <binary> <snapshot>");
            return true;
        }
    };

    print_str(core, &format!("Testing GUID generation: {} vs {}\n", binary_path, snap_path));

    match container.test_guid_generation(core, Path::new(binary_path), Path::new(snap_path)) {
        Ok((matched, total)) => {
            print_str(core, &format!("GUID test: {}/{} matched\n", matched, total));
            true
        }
        Err(e) => {
            show_error(core, &format!("Test failed: {}", e));
            true
        }
    }
}

pub unsafe fn print_str(core: *mut RCore, s: &str) {
    let c_str = CString::new(s).unwrap();
    let cons = crate::r2::ffi::r_core_get_cons(core);
    r_cons_print(cons, c_str.as_ptr());
}

unsafe fn show_error(core: *mut RCore, msg: &str) {
    let c_str = CString::new(format!("ERROR: {}\n", msg)).unwrap();
    let cons = crate::r2::ffi::r_core_get_cons(core);
    r_cons_print(cons, c_str.as_ptr());
}

unsafe fn parse_address(core: *mut RCore, addr_str: &str) -> u64 {
    if addr_str == "$$" {
        let cmd = CString::new("s").unwrap();
        let result = r_core_cmd_str(core, cmd.as_ptr());
        if result.is_null() {
            return 0;
        }
        let s = std::ffi::CStr::from_ptr(result)
            .to_string_lossy()
            .into_owned();
        free(result as *mut _);
        return u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or(0);
    } else if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        u64::from_str_radix(&addr_str[2..], 16).unwrap_or(0)
    } else {
        u64::from_str_radix(addr_str, 16).unwrap_or(0)
    }
}
