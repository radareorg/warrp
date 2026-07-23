use std::collections::HashSet;
use std::ffi::CString;
use std::path::Path;

use uuid::Uuid;

use crate::r2::analysis;
use crate::r2::ffi::{free, r_cons_print, r_core_cmd_str, RCore};
use crate::r2::guid::compute_function_guid;
use crate::warp::container::WarpContainer;
use crate::warp::network::DEFAULT_SOURCE_TAGS;
use crate::warp::signature::FunctionGUID;
use crate::warp::types::Target;

const NETWORK_QUERY_BATCH_SIZE: usize = 10_000;

/// # Safety
/// `core` must be a valid pointer to an r2 RCore instance.
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
        "server" => cmd_server(core, container, subargs),
        "auth" => cmd_auth(core, container, subargs),
        "sources" => cmd_sources(core, container, subargs),
        "source" => cmd_source(core, container, subargs),
        "pull" => cmd_pull(core, container, subargs),
        "push" => cmd_push(core, container, subargs),
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
        "zw server [url]   show or set the WARP server for this session\n",
        "zw auth [token]   show/set API key; use 'zw auth clear' to forget it\n",
        "zw sources        list WARP server sources\n",
        "zw source create <name>  create a writable WARP server source\n",
        "zw pull [source-uuid] [--current]  fetch matching server signatures\n",
        "zw push <source-uuid> [commit-name]  upload current signatures\n",
        "zw test <binary>  test GUID generation against snapshot\n",
        "zw info           show container/target info\n",
        "zw clear          clear loaded containers\n",
    );
    print_str(core, help);
    true
}

unsafe fn cmd_server(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    if args.len() > 1 {
        show_error(core, "Usage: zw server [https://warp.example]");
        return true;
    }

    if let Some(server_url) = args.first() {
        if let Err(error) = container.set_server_url(server_url) {
            show_error(core, &error);
            return true;
        }
    }

    let client = container.network_client();
    print_str(core, &format!("WARP server: {}\n", client.server_url()));
    print_str(
        core,
        &format!(
            "Authentication: {}\n",
            if client.is_authenticated() {
                "API key configured"
            } else {
                "guest (read-only)"
            }
        ),
    );
    match client.status() {
        Ok(status) => print_str(core, &format!("Status: {}\n", status)),
        Err(error) => show_error(core, &format!("Server is unavailable: {}", error)),
    }
    true
}

unsafe fn cmd_auth(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    match args {
        [] => print_str(
            core,
            &format!(
                "WARP API key: {}\n",
                if container.network_client().is_authenticated() {
                    "configured"
                } else {
                    "not configured"
                }
            ),
        ),
        ["clear"] => {
            container.set_server_token(None);
            print_str(core, "WARP API key cleared for this session.\n");
        }
        [token] => {
            container.set_server_token(Some((*token).to_string()));
            print_str(core, "WARP API key configured for this session.\n");
        }
        _ => show_error(core, "Usage: zw auth <token> | zw auth clear"),
    }
    true
}

unsafe fn cmd_sources(core: *mut RCore, container: &WarpContainer, args: &[&str]) -> bool {
    if !args.is_empty() {
        show_error(core, "Usage: zw sources");
        return true;
    }

    match container.network_client().list_sources() {
        Ok(sources) if sources.is_empty() => print_str(core, "No WARP sources are visible.\n"),
        Ok(sources) => {
            print_str(core, "WARP server sources:\n");
            for source in sources {
                print_str(core, &format!("  {}  {}\n", source.id, source.name));
            }
        }
        Err(error) => show_error(core, &format!("Could not list sources: {}", error)),
    }
    true
}

unsafe fn cmd_source(core: *mut RCore, container: &WarpContainer, args: &[&str]) -> bool {
    match args {
        ["create", name] => match container.network_client().create_source(name) {
            Ok(source) => print_str(
                core,
                &format!("Created WARP source '{}' ({})\n", source.name, source.id),
            ),
            Err(error) => show_error(core, &format!("Could not create source: {}", error)),
        },
        _ => show_error(core, "Usage: zw source create <name>"),
    }
    true
}

unsafe fn cmd_pull(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    let (source, current_only) = match parse_pull_args(args) {
        Ok(options) => options,
        Err(error) => {
            show_error(core, &error);
            return true;
        }
    };

    if !analysis::ensure_functions_exist(core) {
        show_error(
            core,
            "No functions found after analysis. Binary may be unsupported.",
        );
        return true;
    }

    let (architecture, platform) = analysis::get_arch_info(core);
    if architecture == "unknown" || platform == "unknown" {
        show_error(
            core,
            "Could not determine the binary target for the WARP server.",
        );
        return true;
    }
    let target = Target::new(architecture, platform);

    if let Some(loaded_target) = container.get_target() {
        if loaded_target.architecture != "unknown" && !loaded_target.matches(&target) {
            show_error(
                core,
                &format!(
                    "Loaded signatures target {}/{} does not match this binary ({}/{}). Use 'zw clear' first.",
                    loaded_target.architecture,
                    loaded_target.platform,
                    target.architecture,
                    target.platform
                ),
            );
            return true;
        }
    }

    let addresses = if current_only {
        match resolve_address(&[], core) {
            Some(address) => vec![address],
            None => return true,
        }
    } else {
        analysis::get_all_functions(core)
    };
    let regions = analysis::get_relocatable_regions(core);
    let mut unique_guids = HashSet::new();
    let mut failed = 0usize;
    for address in addresses {
        match compute_function_guid(core, address, &regions, None) {
            Ok(guid) => {
                unique_guids.insert(FunctionGUID::from_uuid(guid.guid));
            }
            Err(_) => failed += 1,
        }
    }

    if unique_guids.is_empty() {
        show_error(
            core,
            "Could not compute a WARP GUID for any analyzed function.",
        );
        return true;
    }
    let mut guids: Vec<_> = unique_guids.into_iter().collect();
    guids.sort_by_key(ToString::to_string);

    let (server_url, target_id) = {
        let client = container.network_client();
        let server_url = client.server_url().to_string();
        let target_id = match client.target_id(&target) {
            Ok(id) => id,
            Err(error) => {
                show_error(core, &format!("Could not resolve WARP target: {}", error));
                return true;
            }
        };
        (server_url, target_id)
    };

    print_str(
        core,
        &format!(
            "Pulling signatures for {} function GUID(s){}...\n",
            guids.len(),
            source
                .map(|source| format!(" from source {}", source))
                .unwrap_or_default()
        ),
    );

    // Fetch every batch before changing the local container, so a failed request
    // cannot leave a half-imported server response behind.
    let mut responses = Vec::new();
    let source_tags = if source.is_some() {
        &[][..]
    } else {
        DEFAULT_SOURCE_TAGS
    };
    for guid_batch in guids.chunks(NETWORK_QUERY_BATCH_SIZE) {
        let response = match container.network_client().query_functions(
            target_id,
            source,
            source_tags,
            guid_batch,
        ) {
            Ok(response) => response,
            Err(error) => {
                show_error(core, &format!("Could not pull signatures: {}", error));
                return true;
            }
        };
        responses.push(response);
    }

    let origin = source
        .map(|source| format!("{}/{}", server_url, source))
        .unwrap_or(server_url);
    let mut loaded = 0usize;
    for response in responses {
        match container.load_network_response(&response, &origin) {
            Ok(count) => loaded += count,
            Err(error) => {
                show_error(
                    core,
                    &format!("Server returned invalid WARP data: {}", error),
                );
                return true;
            }
        }
    }

    print_str(
        core,
        &format!(
            "Pulled {} signature(s) for {} GUID(s){}{}\n",
            loaded,
            guids.len(),
            if failed == 0 {
                String::new()
            } else {
                format!(" ({} local GUID(s) could not be computed)", failed)
            },
            if loaded == 0 {
                "; no matching server signatures were found".to_string()
            } else {
                String::new()
            }
        ),
    );
    true
}

unsafe fn cmd_push(core: *mut RCore, container: &WarpContainer, args: &[&str]) -> bool {
    let source = match args.first().and_then(|value| Uuid::parse_str(value).ok()) {
        Some(source) => source,
        None => {
            show_error(core, "Usage: zw push <source-uuid> [commit-name]");
            return true;
        }
    };
    if args.len() > 2 {
        show_error(core, "Usage: zw push <source-uuid> [commit-name]");
        return true;
    }

    let bytes = match container.to_warp_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            show_error(
                core,
                &format!("Could not prepare signatures for upload: {}", error),
            );
            return true;
        }
    };
    let name = args.get(1).copied().unwrap_or("r2warp-signatures");

    print_str(
        core,
        &format!(
            "Uploading {} signature(s) to source {}...\n",
            container.function_count(),
            source
        ),
    );
    match container.network_client().push_file(source, &bytes, name) {
        Ok(commit_id) => print_str(
            core,
            &format!("Uploaded WARP signatures as commit {}.\n", commit_id),
        ),
        Err(error) => show_error(core, &format!("Could not upload signatures: {}", error)),
    }
    true
}

fn parse_pull_args(args: &[&str]) -> Result<(Option<Uuid>, bool), String> {
    let mut source = None;
    let mut current_only = false;
    let mut index = 0;

    while index < args.len() {
        match args[index] {
            "--current" | "-c" => current_only = true,
            "--source" | "-s" => {
                if source.is_some() {
                    return Err("Only one WARP source may be specified".to_string());
                }
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "Usage: zw pull [source-uuid] [--current]".to_string())?;
                source = Some(
                    Uuid::parse_str(value)
                        .map_err(|_| format!("Invalid WARP source UUID: {}", value))?,
                );
            }
            value if source.is_none() => {
                source = Some(
                    Uuid::parse_str(value)
                        .map_err(|_| format!("Invalid WARP source UUID: {}", value))?,
                );
            }
            value => return Err(format!("Unexpected pull argument: {}", value)),
        }
        index += 1;
    }

    Ok((source, current_only))
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

    if let Some(target) = container.get_target() {
        print_str(
            core,
            &format!("Target: {} / {}\n", target.architecture, target.platform),
        );
    }

    print_str(
        core,
        &format!("Functions loaded: {}\n", container.function_count()),
    );
    true
}

unsafe fn cmd_load(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    let path = match args.first() {
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
            print_str(
                core,
                &format!("Functions loaded: {}\n", container.function_count()),
            );
            true
        }
        Err(e) => {
            show_error(core, &format!("Failed to load WARP file: {}", e));
            true
        }
    }
}

unsafe fn cmd_save(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    let path = match args.first() {
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

unsafe fn resolve_address(args: &[&str], core: *mut RCore) -> Option<u64> {
    let addr_str = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .copied()
        .unwrap_or("$$");
    match parse_address(core, addr_str) {
        Some(addr) => Some(addr),
        None => {
            show_error(core, "Invalid address");
            None
        }
    }
}

unsafe fn cmd_match(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    if container.function_count() == 0 {
        show_error(core, "No WARP signatures loaded. Use 'zw load' first.");
        return true;
    }

    if !analysis::ensure_functions_exist(core) {
        show_error(
            core,
            "No functions found after analysis. Binary may be unsupported.",
        );
        return true;
    }

    if args.contains(&"-a") {
        return cmd_match_all(core, container);
    }
    match resolve_address(args, core) {
        Some(addr) => cmd_match_single(core, container, addr),
        None => true,
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
                    print_str(
                        core,
                        &format!(
                            "0x{:08x}: {} -> {}{}\n",
                            fcn_addr, best.guid, best.symbol.name, extra
                        ),
                    );
                    matched += 1;
                    if candidates.len() > 1 {
                        ambiguous += 1;
                    }
                } else {
                    unmatched += 1;
                }
            }
            None => match compute_function_guid(core, *fcn_addr, &regions, None) {
                Ok(guid) => {
                    if let Some(matches) = container.find_by_guid(&guid) {
                        if !matches.is_empty() {
                            let name = &matches[0].symbol.name;
                            analysis::apply_function_metadata(core, *fcn_addr, &matches[0]);
                            print_str(core, &format!("0x{:08x}: {} -> {}\n", fcn_addr, guid, name));
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
            },
        }
    }

    print_str(
        core,
        &format!(
            "Matched: {} / {} (ambiguous: {})\n",
            matched,
            matched + unmatched,
            ambiguous
        ),
    );

    true
}

unsafe fn cmd_match_single(core: *mut RCore, container: &WarpContainer, addr: u64) -> bool {
    print_str(core, &format!("Matching function at 0x{:08x}...\n", addr));

    let regions = analysis::get_relocatable_regions(core);

    // Try constraint-based matching first
    if let Some(candidates) = container.match_with_constraints(core, addr, &regions) {
        print_str(
            core,
            &format!("Found {} candidate(s) by GUID:\n", candidates.len()),
        );

        for (i, (func, _score)) in candidates.iter().enumerate() {
            let marker = if i == 0 { "*" } else { " " };
            print_str(
                core,
                &format!(
                    "  {}{}. {} ({} constraints)\n",
                    marker,
                    i + 1,
                    func.symbol.name,
                    func.constraints.len()
                ),
            );
        }

        // Apply best match
        if let Some((best, _score)) = candidates.first() {
            analysis::apply_function_metadata(core, addr, best);
            print_str(core, &format!("Applied: {}\n", best.symbol.name));
        }
        return true;
    }

    // Fallback to GUID-only matching
    let guid = match compute_function_guid(core, addr, &regions, None) {
        Ok(g) => g,
        Err(e) => {
            show_error(core, &format!("Failed to compute function GUID: {}", e));
            return true;
        }
    };

    print_str(
        core,
        &format!("Function GUID: {} (no constraint matches)\n", guid),
    );

    match container.find_by_guid(&guid) {
        Some(matches) if !matches.is_empty() => {
            print_str(core, &format!("Found {} match(es):\n", matches.len()));
            for (i, func) in matches.iter().enumerate() {
                print_str(
                    core,
                    &format!(
                        "  {}. {} (constraints: {})\n",
                        i + 1,
                        func.symbol.name,
                        func.constraints.len()
                    ),
                );
            }

            if matches.len() == 1 {
                let name = &matches[0].symbol.name;
                analysis::apply_function_metadata(core, addr, &matches[0]);
                print_str(core, &format!("Applied: {}\n", name));
            } else {
                print_str(
                    core,
                    "Multiple matches found. Use constraints to disambiguate.\n",
                );
            }
            true
        }
        Some(_) | None => {
            show_error(core, "No matching function found in WARP signatures.");
            true
        }
    }
}

unsafe fn cmd_create(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    if args.contains(&"-a") {
        return cmd_create_all(core, container);
    }
    match resolve_address(args, core) {
        Some(addr) => cmd_create_single(core, container, addr),
        None => true,
    }
}

unsafe fn cmd_create_all(core: *mut RCore, container: &mut WarpContainer) -> bool {
    if !analysis::ensure_functions_exist(core) {
        show_error(
            core,
            "No functions found after analysis. Binary may be unsupported.",
        );
        return true;
    }

    let interactive = analysis::is_interactive(core);
    let cons = crate::r2::ffi::r_core_get_cons(core);
    if interactive {
        print_str(core, "Initializing analysis cache...");
        crate::r2::ffi::r_cons_flush(cons);
    }

    container.initialize_cache(core);
    let functions = container.cache.get_all_functions().to_vec();
    let total = functions.len();
    if total == 0 {
        show_error(core, "No functions found in current binary.");
        return true;
    }

    print_str(
        core,
        &format!("Creating WARP signatures for {} functions...\n", total),
    );

    for (i, fcn_addr) in functions.iter().enumerate() {
        if interactive {
            print_str(core, &format!("\rProcessing {}/{}...", i + 1, total));
            crate::r2::ffi::r_cons_flush(cons);
        }
        if let Err(e) = container.add_function_from_binary(core, *fcn_addr) {
            if interactive {
                print_str(
                    core,
                    &format!(
                        "\nWarning: Failed to add function at 0x{:x}: {}\n",
                        fcn_addr, e
                    ),
                );
            }
        }
    }

    if interactive {
        print_str(core, "\n");
    } else {
        print_str(
            core,
            &format!("Created signatures for {} functions\n", total),
        );
    }
    true
}

unsafe fn cmd_create_single(core: *mut RCore, container: &mut WarpContainer, addr: u64) -> bool {
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
    print_str(
        core,
        &format!("Functions: {}\n", container.function_count()),
    );

    if let Some(target) = container.get_target() {
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

unsafe fn cmd_test(core: *mut RCore, container: &mut WarpContainer, args: &[&str]) -> bool {
    let binary_path = match args.first() {
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

    print_str(
        core,
        &format!(
            "Testing GUID generation: {} vs {}\n",
            binary_path, snap_path
        ),
    );

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

/// # Safety
/// `core` must be a valid pointer to an r2 RCore instance.
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

unsafe fn parse_address(core: *mut RCore, addr_str: &str) -> Option<u64> {
    if addr_str == "$$" {
        let cmd = CString::new("s").unwrap();
        let result = r_core_cmd_str(core, cmd.as_ptr());
        if result.is_null() {
            return None;
        }
        let s = std::ffi::CStr::from_ptr(result)
            .to_string_lossy()
            .into_owned();
        free(result as *mut _);
        parse_address_literal(&s)
    } else {
        parse_address_literal(addr_str)
    }
}

fn parse_address_literal(addr_str: &str) -> Option<u64> {
    let addr_str = addr_str.trim();
    let addr_str = addr_str
        .strip_prefix("0x")
        .or_else(|| addr_str.strip_prefix("0X"))
        .unwrap_or(addr_str);
    u64::from_str_radix(addr_str, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{parse_address_literal, parse_pull_args};
    use uuid::Uuid;

    #[test]
    fn parse_pull_accepts_source_and_current_flag_in_any_order() {
        let source = "01234567-89ab-cdef-0123-456789abcdef";
        let (parsed_source, current_only) = parse_pull_args(&["--current", source]).unwrap();

        assert_eq!(parsed_source, Some(Uuid::parse_str(source).unwrap()));
        assert!(current_only);
    }

    #[test]
    fn parse_pull_rejects_multiple_sources() {
        let error = parse_pull_args(&[
            "--source",
            "01234567-89ab-cdef-0123-456789abcdef",
            "--source",
            "fedcba98-7654-3210-fedc-ba9876543210",
        ])
        .unwrap_err();

        assert_eq!(error, "Only one WARP source may be specified");
    }

    #[test]
    fn parse_address_accepts_zero() {
        assert_eq!(parse_address_literal("0"), Some(0));
        assert_eq!(parse_address_literal("invalid"), None);
    }
}
