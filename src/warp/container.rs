use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use uuid::Uuid;

use crate::r2::analysis::RelocatableRegion;
use crate::r2::cache::AnalysisCache;
use crate::r2::ffi::RCore;
use crate::r2::guid::FunctionGUID as R2FunctionGUID;
use crate::warp::signature::{Constraint, Function, FunctionGUID, Symbol};
use crate::warp::types::Target;

enum ConstraintType {
    Constraint(Uuid),
}

#[derive(Debug)]
pub struct WarpFile {
    pub path: String,
    pub target: Target,
}

pub struct WarpContainer {
    loaded_files: Vec<WarpFile>,
    target: Option<Target>,
    functions: HashMap<[u8; 16], Vec<Function>>,
    function_count: usize,
    pub cache: AnalysisCache,
}

impl WarpContainer {
    pub fn new() -> Self {
        Self {
            loaded_files: Vec::new(),
            target: None,
            functions: HashMap::new(),
            function_count: 0,
            cache: AnalysisCache::new(),
        }
    }

    /// Load a WARP file into memory
    pub fn load(&mut self, path: &Path) -> Result<(), String> {
        let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        // Parse WARP file (FlatBuffers format)
        let warp_data = Self::parse_warp_file(&bytes)?;

        // Check target compatibility
        if let Some(ref current_target) = self.target {
            if !current_target.matches(&warp_data.target) {
                return Err(format!(
                    "Target mismatch: expected {}/{}, got {}/{}",
                    current_target.architecture,
                    current_target.platform,
                    warp_data.target.architecture,
                    warp_data.target.platform
                ));
            }
        } else {
            self.target = Some(warp_data.target.clone());
        }

        // Index functions by GUID
        for func in warp_data.functions {
            let guid = func.guid.bytes;
            self.functions.entry(guid).or_default().push(func);
            self.function_count += 1;
        }

        self.loaded_files.push(WarpFile {
            path: path.display().to_string(),
            target: warp_data.target,
        });

        Ok(())
    }

    /// Parse WARP file using the warp crate
    fn parse_warp_file(bytes: &[u8]) -> Result<WarpData, String> {
        // Try to parse as FlatBuffers WARP file
        if let Some(warp_file) = warp::WarpFile::from_bytes(bytes) {
            return Self::extract_from_warp_file(&warp_file);
        }

        // Fallback: try JSON format for testing
        if let Ok(json_data) = serde_json::from_slice::<serde_json::Value>(bytes) {
            return Self::parse_json_warp(&json_data);
        }

        Err("Invalid WARP file format".to_string())
    }

    fn extract_from_warp_file(warp_file: &warp::WarpFile) -> Result<WarpData, String> {
        use warp::chunk::ChunkKind;

        let mut functions = Vec::new();
        let mut target = Target::default();

        for chunk in &warp_file.chunks {
            target = Target::new(
                chunk.header.target.architecture.clone().unwrap_or_default(),
                chunk.header.target.platform.clone().unwrap_or_default(),
            );

            if let ChunkKind::Signature(sig_chunk) = &chunk.kind {
                for func in sig_chunk.functions() {
                    let guid_bytes = func.guid.as_bytes();
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(guid_bytes);

                    let name = func.symbol.name.clone();

                    let mut function =
                        Function::new(FunctionGUID { bytes }, Symbol::function(name));

                    let mut constraints = std::collections::HashSet::new();
                    for constraint in func.constraints.iter() {
                        let constraint_guid = Uuid::from_bytes(constraint.guid.guid.into_bytes());
                        let offset = constraint.offset.unwrap_or(0);
                        let c = Constraint::from_constraint_guid(constraint_guid, offset);
                        constraints.insert(c);
                    }
                    function.constraints = constraints.into_iter().collect();

                    functions.push(function);
                }
            }
        }

        Ok(WarpData { target, functions })
    }

    fn parse_json_warp(json: &serde_json::Value) -> Result<WarpData, String> {
        let obj = json.as_object().ok_or("Expected JSON object")?;

        // Extract target
        let target = if let Some(target_obj) = obj.get("target") {
            Target::new(
                target_obj
                    .get("architecture")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                target_obj
                    .get("platform")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            )
        } else {
            Target::default()
        };

        // Extract functions
        let functions = if let Some(funcs_arr) = obj.get("functions").and_then(|v| v.as_array()) {
            funcs_arr
                .iter()
                .filter_map(Self::parse_json_function)
                .collect()
        } else {
            Vec::new()
        };

        Ok(WarpData { target, functions })
    }

    fn parse_json_function(json: &serde_json::Value) -> Option<Function> {
        let obj = json.as_object()?;

        let guid_str = obj.get("guid")?.as_str()?;
        let guid = FunctionGUID::from_uuid(uuid::Uuid::parse_str(guid_str).ok()?);

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Some(Function::new(guid, Symbol::function(name)))
    }

    /// Save signatures to a WARP file
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::collections::HashSet;
        use std::fs::File;
        use std::io::Write;
        use uuid::Uuid;
        use warp::chunk::{Chunk, ChunkKind, CompressionType};
        use warp::signature::chunk::SignatureChunk;
        use warp::signature::comment::FunctionComment;
        use warp::signature::constraint::Constraint as WarpConstraint;
        use warp::signature::function::Function as WarpFunction;
        use warp::signature::function::FunctionGUID as WarpFunctionGUID;
        use warp::symbol::Symbol as WarpSymbol;
        use warp::symbol::SymbolClass;
        use warp::symbol::SymbolModifiers;
        use warp::target::Target as WarpTarget;
        use warp::{WarpFile, WarpFileHeader};

        let warp_functions: Vec<WarpFunction> = self
            .functions
            .values()
            .flat_map(|funcs| funcs.iter())
            .map(|f| {
                let guid = WarpFunctionGUID::from(Uuid::from_bytes(f.guid.bytes));
                let symbol = WarpSymbol::new(
                    f.symbol.name.clone(),
                    match f.symbol.class {
                        crate::warp::signature::SymbolClass::Function => SymbolClass::Function,
                        crate::warp::signature::SymbolClass::Data => SymbolClass::Data,
                        crate::warp::signature::SymbolClass::Bare => SymbolClass::Bare,
                    },
                    f.symbol
                        .modifiers
                        .iter()
                        .map(|m| match m {
                            crate::warp::signature::SymbolModifiers::External => {
                                SymbolModifiers::External
                            }
                            crate::warp::signature::SymbolModifiers::Exported => {
                                SymbolModifiers::Exported
                            }
                        })
                        .collect(),
                );

                let warp_constraints: HashSet<WarpConstraint> = f
                    .constraints
                    .iter()
                    .filter_map(|c| {
                        if let Some(guid) = &c.guid {
                            Some(WarpConstraint::from_function(
                                &WarpFunctionGUID::from(Uuid::from_bytes(guid.bytes)),
                                Some(c.offset),
                            ))
                        } else if let Some(sym) = &c.symbol {
                            let warp_sym = WarpSymbol::new(
                                sym.name.clone(),
                                match sym.class {
                                    crate::warp::signature::SymbolClass::Function => {
                                        SymbolClass::Function
                                    }
                                    crate::warp::signature::SymbolClass::Data => SymbolClass::Data,
                                    crate::warp::signature::SymbolClass::Bare => SymbolClass::Bare,
                                },
                                sym.modifiers
                                    .iter()
                                    .map(|m| match m {
                                        crate::warp::signature::SymbolModifiers::External => {
                                            SymbolModifiers::External
                                        }
                                        crate::warp::signature::SymbolModifiers::Exported => {
                                            SymbolModifiers::Exported
                                        }
                                    })
                                    .collect(),
                            );
                            Some(WarpConstraint::from_symbol(&warp_sym, Some(c.offset)))
                        } else {
                            None
                        }
                    })
                    .collect();

                WarpFunction {
                    guid,
                    symbol,
                    ty: None,
                    constraints: warp_constraints,
                    comments: f
                        .comments
                        .iter()
                        .map(|c| FunctionComment {
                            offset: c.offset,
                            text: c.text.clone(),
                        })
                        .collect(),
                    variables: vec![],
                }
            })
            .collect();

        if warp_functions.is_empty() {
            return Err("No functions to save".to_string());
        }

        // Create signature chunk
        let sig_chunk =
            SignatureChunk::new(&warp_functions).ok_or("Failed to create signature chunk")?;

        // Create target
        let target = WarpTarget {
            architecture: self.target.as_ref().map(|t| t.architecture.clone()),
            platform: self.target.as_ref().map(|t| t.platform.clone()),
        };

        // Create chunk with header
        let chunk = Chunk::new_with_target(
            ChunkKind::Signature(sig_chunk),
            CompressionType::None,
            target,
        );

        // Create WARP file
        let warp_file = WarpFile::new(WarpFileHeader::new(), vec![chunk]);

        // Serialize to bytes
        let bytes = warp_file.to_bytes();

        // Write to file
        let mut file = File::create(path).map_err(|e| format!("Failed to create file: {}", e))?;

        file.write_all(&bytes)
            .map_err(|e| format!("Failed to write file: {}", e))?;

        Ok(())
    }

    /// Find functions matching a GUID
    pub fn find_by_guid(&self, guid: &R2FunctionGUID) -> Option<&[Function]> {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(guid.as_bytes());
        self.functions.get(&bytes).map(|v| v.as_slice())
    }

    // Match function with constraint-based disambiguation
    ///
    /// When multiple functions have the same GUID, use constraints to pick the best match.
    /// Returns (function index, match score) for each candidate.
    ///
    /// # Safety
    /// `core` must be a valid pointer to an r2 RCore instance.
    pub unsafe fn match_with_constraints(
        &self,
        core: *mut RCore,
        addr: u64,
        regions: &[RelocatableRegion],
    ) -> Option<Vec<(&Function, usize)>> {
        let guid = crate::r2::guid::compute_function_guid(core, addr, regions, None).ok()?;
        let candidates = self.find_by_guid(&guid)?;

        if candidates.is_empty() {
            return None;
        }

        // If only one candidate, no need to check constraints
        if candidates.len() == 1 {
            return Some(vec![(candidates.first()?, 100)]);
        }

        // Collect constraints from the binary for this function
        let binary_constraints = self.collect_binary_constraints(core, addr, regions);

        // Score each candidate by constraint matches
        let mut scored: Vec<_> = candidates
            .iter()
            .map(|candidate| {
                let score =
                    self.score_constraint_match(&binary_constraints, &candidate.constraints);
                (candidate, score)
            })
            .collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.1.cmp(&a.1));

        Some(scored)
    }

    /// Collect constraints for a function in the current binary
    unsafe fn collect_binary_constraints(
        &self,
        core: *mut RCore,
        addr: u64,
        regions: &[RelocatableRegion],
    ) -> Vec<(i64, ConstraintType)> {
        use crate::warp::constraint::clean_symbol_name;
        use crate::warp::signature::NAMESPACE_CONSTRAINT;

        let func_start = match crate::r2::analysis::get_function_at(core, addr) {
            Some(f) => f.addr,
            None => return Vec::new(),
        };

        let mut constraints = Vec::new();

        let cmd = std::ffi::CString::new(format!("axfj @ 0x{:x}", addr)).unwrap();
        let result = crate::r2::ffi::r_core_cmd_str(core, cmd.as_ptr());

        if !result.is_null() {
            let json_str = std::ffi::CStr::from_ptr(result)
                .to_string_lossy()
                .into_owned();
            crate::r2::ffi::free(result as *mut _);

            if let Ok(xrefs) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
                for xref in xrefs {
                    if xref.get("type").and_then(|v| v.as_str()).unwrap_or("") != "CALL" {
                        continue;
                    }
                    let call_site = xref.get("from").and_then(|v| v.as_u64()).unwrap_or(0);
                    let call_target = xref.get("to").and_then(|v| v.as_u64()).unwrap_or(0);
                    if call_target == 0 {
                        continue;
                    }

                    let offset = call_site as i64 - func_start as i64;

                    if let Ok(target_guid) =
                        crate::r2::guid::compute_function_guid(core, call_target, regions, None)
                    {
                        constraints.push((
                            offset,
                            ConstraintType::Constraint(Uuid::new_v5(
                                &NAMESPACE_CONSTRAINT,
                                target_guid.as_bytes(),
                            )),
                        ));
                    }

                    let sym_cmd =
                        std::ffi::CString::new(format!("is.j @ 0x{:x}", call_target)).unwrap();
                    let sym_result = crate::r2::ffi::r_core_cmd_str(core, sym_cmd.as_ptr());
                    if !sym_result.is_null() {
                        let sym_str = std::ffi::CStr::from_ptr(sym_result)
                            .to_string_lossy()
                            .into_owned();
                        crate::r2::ffi::free(sym_result as *mut _);
                        if let Ok(symbols) =
                            serde_json::from_str::<Vec<serde_json::Value>>(&sym_str)
                        {
                            if let Some(name) = symbols
                                .first()
                                .and_then(|s| s.get("name"))
                                .and_then(|n| n.as_str())
                            {
                                constraints.push((
                                    offset,
                                    ConstraintType::Constraint(Uuid::new_v5(
                                        &NAMESPACE_CONSTRAINT,
                                        clean_symbol_name(name).as_bytes(),
                                    )),
                                ));
                            }
                        }
                    }
                }
            }
        }

        let all_funcs = crate::r2::analysis::get_all_functions(core);
        let mut sorted_funcs: Vec<u64> = all_funcs.into_iter().collect();
        sorted_funcs.sort();

        if let Ok(pos) = sorted_funcs.binary_search(&addr) {
            for &adj_addr in sorted_funcs
                .iter()
                .take(pos.min(sorted_funcs.len()))
                .skip(pos.saturating_sub(2))
            {
                self.add_adjacency_constraints(
                    core,
                    adj_addr,
                    func_start,
                    regions,
                    &mut constraints,
                );
            }
            for &adj_addr in sorted_funcs
                .iter()
                .take((pos + 3).min(sorted_funcs.len()))
                .skip(pos + 1)
            {
                self.add_adjacency_constraints(
                    core,
                    adj_addr,
                    func_start,
                    regions,
                    &mut constraints,
                );
            }
        }

        constraints
    }

    unsafe fn add_adjacency_constraints(
        &self,
        core: *mut RCore,
        adj_addr: u64,
        func_start: u64,
        regions: &[RelocatableRegion],
        constraints: &mut Vec<(i64, ConstraintType)>,
    ) {
        use crate::warp::constraint::clean_symbol_name;
        use crate::warp::signature::NAMESPACE_CONSTRAINT;
        let offset = adj_addr as i64 - func_start as i64;

        if let Ok(guid) = crate::r2::guid::compute_function_guid(core, adj_addr, regions, None) {
            constraints.push((
                offset,
                ConstraintType::Constraint(Uuid::new_v5(&NAMESPACE_CONSTRAINT, guid.as_bytes())),
            ));
        }

        if let Some(adj_info) = crate::r2::analysis::get_function_at(core, adj_addr) {
            if let Some(name) = adj_info.name {
                constraints.push((
                    offset,
                    ConstraintType::Constraint(Uuid::new_v5(
                        &NAMESPACE_CONSTRAINT,
                        clean_symbol_name(&name).as_bytes(),
                    )),
                ));
            }
        }
    }

    /// Score how well binary constraints match signature constraints
    fn score_constraint_match(
        &self,
        binary_constraints: &[(i64, ConstraintType)],
        sig_constraints: &[Constraint],
    ) -> usize {
        if sig_constraints.is_empty() {
            return 50;
        }
        let mut matches = 0;
        let total = sig_constraints.len();

        for sig_c in sig_constraints {
            let Some(sig_cguid) = &sig_c.constraint_guid else {
                continue;
            };
            for (offset, binary_c) in binary_constraints {
                if (sig_c.offset - offset).abs() > 16 {
                    continue;
                }
                let ConstraintType::Constraint(binary_cguid) = binary_c;
                if sig_cguid == binary_cguid {
                    matches += 1;
                    break;
                }
            }
        }

        (matches * 100) / total.max(1)
    }

    /// Initialize the analysis cache (call before add_function_from_binary for batch operations)
    ///
    /// # Safety
    /// `core` must be a valid pointer to an r2 RCore instance.
    pub unsafe fn initialize_cache(&mut self, core: *mut RCore) {
        self.cache.initialize(core);
    }

    /// Add a function from radare2 analysis using cached data
    ///
    /// # Safety
    /// `core` must be a valid pointer to an r2 RCore instance.
    pub unsafe fn add_function_from_binary(
        &mut self,
        core: *mut RCore,
        addr: u64,
    ) -> Result<FunctionGUID, String> {
        // Initialize cache if needed
        if self.cache.get_all_functions().is_empty() {
            self.cache.initialize(core);
        }

        // Set target from binary if not already set
        if self.target.is_none() {
            let (arch, platform) = crate::r2::analysis::get_arch_info(core);
            self.target = Some(Target::new(arch, platform));
        }

        // Use cached GUID computation
        let guid_uuid = self
            .cache
            .get_or_compute_guid(core, addr)
            .ok_or_else(|| format!("Failed to compute GUID for 0x{:x}", addr))?;

        // Get function name from cache
        let name = self
            .cache
            .get_function(addr)
            .and_then(|f| f.name.clone())
            .unwrap_or_else(|| format!("fcn_{:08x}", addr));

        // Collect constraints using cache
        let constraints = self.collect_constraints(core, addr);

        let mut func = Function::new(FunctionGUID::from_uuid(guid_uuid), Symbol::function(name));
        func.constraints = constraints.into_iter().collect();

        let guid_bytes = func.guid.bytes;
        self.functions.entry(guid_bytes).or_default().push(func);
        self.function_count += 1;

        Ok(FunctionGUID::from_uuid(guid_uuid))
    }

    /// Collect constraints for a function
    unsafe fn collect_constraints(
        &self,
        core: *mut RCore,
        addr: u64,
    ) -> std::collections::HashSet<Constraint> {
        use std::collections::HashSet as StdHashSet;

        let mut constraints = StdHashSet::new();

        // Get function start
        let func_info = match self.cache.get_function(addr) {
            Some(info) => info,
            None => return constraints,
        };
        let func_start = func_info.addr;

        // Collect call-site constraints (calls FROM this function)
        for xref in self.cache.get_xrefs_from_function(addr) {
            let call_site = xref.from;
            let call_target = xref.to;

            if call_target == 0 {
                continue;
            }

            let call_site_offset = call_site as i64 - func_start as i64;

            // Check if target is internal function
            if self.cache.is_internal_function(call_target) {
                // Internal function - use cached GUID
                if let Some(target_guid) = self.cache.get_or_compute_guid(core, call_target) {
                    let constraint = Constraint::from_function(
                        &FunctionGUID::from_uuid(target_guid),
                        Some(call_site_offset),
                    );
                    constraints.insert(constraint);
                }
            } else {
                // External/import - use symbol name from xref
                if let Some(ref name) = xref.name {
                    let cleaned = crate::warp::constraint::clean_symbol_name(name);
                    let symbol =
                        Symbol::new(cleaned, crate::warp::signature::SymbolClass::Function);
                    let constraint = Constraint::from_symbol(&symbol, Some(call_site_offset));
                    constraints.insert(constraint);
                }
            }
        }

        // Collect adjacency constraints (functions before/after)
        for adj_addr in self.cache.get_adjacent_functions(addr) {
            let offset = adj_addr as i64 - func_start as i64;

            // GUID constraint (cached)
            if let Some(adj_guid) = self.cache.get_or_compute_guid(core, adj_addr) {
                let constraint =
                    Constraint::from_function(&FunctionGUID::from_uuid(adj_guid), Some(offset));
                constraints.insert(constraint);
            }

            // Symbol constraint
            if let Some(adj_info) = self.cache.get_function(adj_addr) {
                if let Some(ref name) = adj_info.name {
                    let cleaned = crate::warp::constraint::clean_symbol_name(name);
                    let symbol =
                        Symbol::new(cleaned, crate::warp::signature::SymbolClass::Function);
                    let constraint = Constraint::from_symbol(&symbol, Some(offset));
                    constraints.insert(constraint);
                }
            }
        }

        constraints
    }

    /// Legacy method for compatibility - uses uncached path
    ///
    /// # Safety
    /// `core` must be a valid pointer to an r2 RCore instance.
    pub unsafe fn add_function_from_binary_legacy(
        &mut self,
        core: *mut RCore,
        addr: u64,
        regions: &[RelocatableRegion],
    ) -> Result<FunctionGUID, String> {
        let guid = crate::r2::guid::compute_function_guid(core, addr, regions, None)?;

        let func_info = crate::r2::analysis::get_function_at(core, addr);
        let name = func_info
            .and_then(|f| f.name)
            .unwrap_or_else(|| format!("fcn_{:08x}", addr));

        let mut func = Function::new(FunctionGUID::from_uuid(guid.guid), Symbol::function(name));
        func.constraints = Vec::new();

        let guid_bytes = func.guid.bytes;
        self.functions.entry(guid_bytes).or_default().push(func);
        self.function_count += 1;

        Ok(FunctionGUID::from_uuid(guid.guid))
    }

    /// Clear all loaded signatures
    pub fn clear(&mut self) {
        self.loaded_files.clear();
        self.functions.clear();
        self.target = None;
        self.function_count = 0;
    }

    /// Get list of loaded files
    pub fn list_files(&self) -> Vec<&str> {
        self.loaded_files.iter().map(|f| f.path.as_str()).collect()
    }

    /// Get the current target
    pub fn get_target(&self) -> Option<&Target> {
        self.target.as_ref()
    }

    /// Get the number of loaded functions
    pub fn function_count(&self) -> usize {
        self.function_count
    }

    /// Get the number of loaded files
    pub fn file_count(&self) -> usize {
        self.loaded_files.len()
    }

    /// Test GUID generation against a snapshot file
    pub fn test_guid_generation(
        &self,
        _core: *mut RCore,
        _binary_path: &Path,
        _snapshot_path: &Path,
    ) -> Result<(usize, usize), String> {
        // TODO: Implement snapshot comparison
        // Load snapshot, compute GUIDs for binary, compare
        Err("GUID testing not yet implemented".to_string())
    }
}

struct WarpData {
    target: Target,
    functions: Vec<Function>,
}

impl Default for WarpContainer {
    fn default() -> Self {
        Self::new()
    }
}
