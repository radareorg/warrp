use std::collections::HashMap;
use std::path::Path;
use std::fs::File;
use std::io::Read;

use crate::r2::ffi::RCore;
use crate::r2::guid::FunctionGUID as R2FunctionGUID;
use crate::r2::analysis::RelocatableRegion;
use crate::warp::signature::{Function, FunctionGUID, Symbol};
use crate::warp::types::Target;

#[derive(Debug)]
pub struct WarpFile {
    pub path: String,
    pub target: Target,
}

pub struct WarpContainer {
    loaded_files: Vec<WarpFile>,
    target: Option<Target>,
    /// GUID -> Functions lookup
    functions: HashMap<[u8; 16], Vec<Function>>,
    /// Function count for quick access
    function_count: usize,
}

impl WarpContainer {
    pub fn new() -> Self {
        Self {
            loaded_files: Vec::new(),
            target: None,
            functions: HashMap::new(),
            function_count: 0,
        }
    }
    
    /// Load a WARP file into memory
    pub fn load(&mut self, path: &Path) -> Result<(), String> {
        let mut file = File::open(path)
            .map_err(|e| format!("Failed to open file: {}", e))?;
        
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
            self.functions
                .entry(guid)
                .or_insert_with(Vec::new)
                .push(func);
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
        
        // Extract target from chunks
        for chunk in &warp_file.chunks {
            // Target is always present in the header
            target = Target::new(
                chunk.header.target.architecture.clone().unwrap_or_default(),
                chunk.header.target.platform.clone().unwrap_or_default(),
            );
            
            // Extract functions from signature chunks
            if let ChunkKind::Signature(sig_chunk) = &chunk.kind {
                // Use the functions() iterator to get owned Function objects
                for func in sig_chunk.functions() {
                    let guid_bytes = func.guid.as_bytes();
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(guid_bytes);
                    
                    let name = func.symbol.name.clone();
                    
                    let function = Function::new(
                        FunctionGUID { bytes },
                        Symbol::function(name),
                    );
                    
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
                target_obj.get("architecture")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                target_obj.get("platform")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
            )
        } else {
            Target::default()
        };
        
        // Extract functions
        let functions = if let Some(funcs_arr) = obj.get("functions").and_then(|v| v.as_array()) {
            funcs_arr.iter()
                .filter_map(|f| Self::parse_json_function(f))
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
        
        let name = obj.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        
        Some(Function::new(guid, Symbol::function(name)))
    }
    
    /// Save signatures to a WARP file
    pub fn save(&self, path: &Path) -> Result<(), String> {
        use std::fs::File;
        use std::io::Write;
        use std::collections::HashSet;
        use warp::chunk::{Chunk, ChunkKind, CompressionType};
        use warp::signature::chunk::SignatureChunk;
        use warp::signature::function::Function as WarpFunction;
        use warp::signature::function::FunctionGUID as WarpFunctionGUID;
        use warp::symbol::Symbol as WarpSymbol;
        use warp::symbol::SymbolClass;
        use warp::symbol::SymbolModifiers;
        use warp::signature::comment::FunctionComment;
        use warp::target::Target as WarpTarget;
        use warp::{WarpFile, WarpFileHeader};
        use uuid::Uuid;
        
        // Convert our functions to warp format
        let warp_functions: Vec<WarpFunction> = self.functions
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
                    f.symbol.modifiers.iter().map(|m| {
                        match m {
                            crate::warp::signature::SymbolModifiers::External => SymbolModifiers::External,
                            crate::warp::signature::SymbolModifiers::Exported => SymbolModifiers::Exported,
                        }
                    }).collect(),
                );
                
                WarpFunction {
                    guid,
                    symbol,
                    ty: None,
                    constraints: HashSet::new(),
                    comments: f.comments.iter().map(|c| {
                        FunctionComment {
                            offset: c.offset,
                            text: c.text.clone(),
                        }
                    }).collect(),
                    variables: vec![],
                }
            })
            .collect();
        
        if warp_functions.is_empty() {
            return Err("No functions to save".to_string());
        }
        
        // Create signature chunk
        let sig_chunk = SignatureChunk::new(&warp_functions)
            .ok_or("Failed to create signature chunk")?;
        
        // Create target
        let target = WarpTarget {
            architecture: self.target.as_ref()
                .map(|t| t.architecture.clone()),
            platform: self.target.as_ref()
                .map(|t| t.platform.clone()),
        };
        
        // Create chunk with header
        let chunk = Chunk::new_with_target(
            ChunkKind::Signature(sig_chunk),
            CompressionType::None,
            target,
        );
        
        // Create WARP file
        let warp_file = WarpFile::new(
            WarpFileHeader::new(),
            vec![chunk],
        );
        
        // Serialize to bytes
        let bytes = warp_file.to_bytes();
        
        // Write to file
        let mut file = File::create(path)
            .map_err(|e| format!("Failed to create file: {}", e))?;
        
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
    
    /// Add a function from radare2 analysis
    pub unsafe fn add_function_from_binary(
        &mut self,
        core: *mut RCore,
        addr: u64,
        regions: &[RelocatableRegion],
    ) -> Result<FunctionGUID, String> {
        // Compute GUID from the function
        let guid = crate::r2::guid::compute_function_guid(core, addr, regions)?;
        
        // Get function name
        let func_info = crate::r2::analysis::get_function_at(core, addr);
        let name = func_info
            .and_then(|f| f.name)
            .unwrap_or_else(|| format!("fcn_{:08x}", addr));
        
        let func = Function::new(FunctionGUID::from_uuid(guid.guid), Symbol::function(name));
        
        let guid_bytes = func.guid.bytes;
        self.functions
            .entry(guid_bytes)
            .or_insert_with(Vec::new)
            .push(func);
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
        self.loaded_files.iter()
            .map(|f| f.path.as_str())
            .collect()
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