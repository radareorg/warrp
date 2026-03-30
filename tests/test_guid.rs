#[cfg(test)]
mod tests {
    use uuid::Uuid;
    
    use crate::r2::guid::{NAMESPACE_BASICBLOCK, NAMESPACE_FUNCTION, FunctionGUID, BasicBlockGUID};
    use crate::warp::signature::{Symbol, SymbolClass};
    use crate::warp::types::Target;
    
    #[test]
    fn test_namespace_constants() {
        // Test that the namespace UUIDs match the WARP spec
        let bb_namespace: Uuid = NAMESPACE_BASICBLOCK;
        let func_namespace: Uuid = NAMESPACE_FUNCTION;
        
        // These should match the values in the WARP spec
        assert_eq!(
            bb_namespace.to_string(),
            "0192a178-7a5f-7936-8653-3cbaa7d6afe7"
        );
        assert_eq!(
            func_namespace.to_string(),
            "0192a179-61ac-7cef-88ed-012296e9492f"
        );
    }
    
    #[test]
    fn test_basic_block_guid() {
        // Create a basic block GUID from some bytes
        let bytes = vec![0x55, 0x48, 0x89, 0xe5]; // push rbp; mov rbp, rsp
        let bg = BasicBlockGUID::from_bytes(0x1000, &bytes);
        
        // The GUID should be deterministic
        let bg2 = BasicBlockGUID::from_bytes(0x1000, &bytes);
        assert_eq!(bg.guid, bg2.guid);
        
        // Different bytes should produce different GUID
        let bytes2 = vec![0x55, 0x48, 0x89, 0xe6]; // Different last byte
        let bg3 = BasicBlockGUID::from_bytes(0x1000, &bytes2);
        assert_ne!(bg.guid, bg3.guid);
    }
    
    #[test]
    fn test_function_guid() {
        // Create a function GUID from basic block GUIDs
        let bytes1 = vec![0x55];
        let bytes2 = vec![0xc3]; // ret
        
        let bg1 = BasicBlockGUID::from_bytes(0x1000, &bytes1);
        let bg2 = BasicBlockGUID::from_bytes(0x1001, &bytes2);
        
        let fg = FunctionGUID::from_basic_blocks(&[bg1.clone(), bg2.clone()]);
        let fg2 = FunctionGUID::from_basic_blocks(&[bg2, bg1]); // Different order
        
        // Order matters for sorting (highest to lowest address)
        assert_ne!(fg.guid, fg2.guid);
    }
    
    #[test]
    fn test_symbol_creation() {
        let sym = Symbol::function("test_function".to_string());
        assert_eq!(sym.name, "test_function");
        assert_eq!(sym.class, SymbolClass::Function);
    }
    
    #[test]
    fn test_target_matching() {
        let t1 = Target::new("x86_64".to_string(), "linux-64".to_string());
        let t2 = Target::new("x86_64".to_string(), "linux-64".to_string());
        assert!(t1.matches(&t2));
        
        let t3 = Target::new("x86_64".to_string(), "windows-64".to_string());
        assert!(!t1.matches(&t3));
        
        let t4 = Target::new("arm64".to_string(), "linux-64".to_string());
        assert!(!t1.matches(&t4));
    }
}