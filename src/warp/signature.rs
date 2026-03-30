use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::r2::guid::FunctionGUID as R2FunctionGUID;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionGUID {
    pub bytes: [u8; 16],
}

impl FunctionGUID {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }
    
    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self { bytes: *uuid.as_bytes() }
    }
    
    pub fn to_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.bytes)
    }
}

impl std::fmt::Display for FunctionGUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_uuid())
    }
}

impl From<R2FunctionGUID> for FunctionGUID {
    fn from(g: R2FunctionGUID) -> Self {
        FunctionGUID::from_uuid(g.guid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SymbolModifiers {
    External = 0,
    Exported = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolClass {
    Function = 0,
    Data = 1,
    Bare = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub modifiers: HashSet<SymbolModifiers>,
    pub class: SymbolClass,
}

impl Hash for Symbol {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.class.hash(state);
        let mut mods: Vec<_> = self.modifiers.iter().collect();
        mods.sort();
        for m in mods {
            m.hash(state);
        }
    }
}

impl Symbol {
    pub fn new(name: String, class: SymbolClass) -> Self {
        Self {
            name,
            modifiers: HashSet::new(),
            class,
        }
    }
    
    pub fn function(name: String) -> Self {
        Self::new(name, SymbolClass::Function)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Constraint {
    pub guid: Option<FunctionGUID>,
    pub symbol: Option<Symbol>,
    pub offset: i64,
}

impl Constraint {
    pub fn from_function(guid: &FunctionGUID, offset: Option<i64>) -> Self {
        Self {
            guid: Some(guid.clone()),
            symbol: None,
            offset: offset.unwrap_or(0),
        }
    }

    pub fn from_symbol(symbol: &Symbol, offset: Option<i64>) -> Self {
        Self {
            guid: None,
            symbol: Some(symbol.clone()),
            offset: offset.unwrap_or(0),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionComment {
    pub offset: i64,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct FunctionVariable {
    pub offset: i64,
    pub name: String,
    pub location: VariableLocation,
    pub var_type: Option<Type>,
}

#[derive(Debug, Clone)]
pub enum VariableLocation {
    Register { id: u64 },
    Stack { offset: i64 },
}

#[derive(Debug, Clone)]
pub struct Function {
    pub guid: FunctionGUID,
    pub symbol: Symbol,
    pub func_type: Option<Type>,
    pub constraints: Vec<Constraint>,
    pub comments: Vec<FunctionComment>,
    pub variables: Vec<FunctionVariable>,
}

impl Function {
    pub fn new(guid: FunctionGUID, symbol: Symbol) -> Self {
        Self {
            guid,
            symbol,
            func_type: None,
            constraints: Vec::new(),
            comments: Vec::new(),
            variables: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TypeClass {
    Void,
    Boolean { width: Option<u16> },
    Integer { width: Option<u16>, signed: bool },
    Float { width: Option<u16> },
    Character { width: Option<u16> },
    Pointer { child: Box<Type>, width: Option<u16> },
    Array { element: Box<Type>, length: Option<u64> },
    Structure { members: Vec<StructureMember> },
    Enumeration { variants: Vec<EnumVariant> },
    Union { members: Vec<UnionMember> },
    Function { calling_convention: String, params: Vec<Type>, return_type: Box<Type> },
    Referrer { name: String },
}

#[derive(Debug, Clone)]
pub struct StructureMember {
    pub name: String,
    pub offset: u64,
    pub member_type: Type,
}

#[derive(Debug, Clone)]
pub struct EnumVariant {
    pub name: String,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct UnionMember {
    pub name: String,
    pub member_type: Type,
}

#[derive(Debug, Clone)]
pub struct Type {
    pub name: Option<String>,
    pub class: TypeClass,
    pub alignment: Option<u16>,
    pub confidence: u8,
}

impl Type {
    pub fn void() -> Self {
        Self {
            name: None,
            class: TypeClass::Void,
            alignment: None,
            confidence: 255,
        }
    }
    
    pub fn integer(bits: u16, signed: bool) -> Self {
        Self {
            name: None,
            class: TypeClass::Integer { width: Some(bits), signed },
            alignment: None,
            confidence: 255,
        }
    }
    
    pub fn pointer(child: Type) -> Self {
        Self {
            name: None,
            class: TypeClass::Pointer { child: Box::new(child), width: None },
            alignment: None,
            confidence: 255,
        }
    }
}