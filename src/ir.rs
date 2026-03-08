#[derive(Debug, Clone)]
pub enum IrExpr {
    Predicate(IrPredicate),
    All(Vec<IrExpr>),
    Any(Vec<IrExpr>),
    FollowedBy(Vec<IrExpr>),
    Qualified(Box<IrExpr>, Vec<IrQualifier>),
}

#[derive(Debug, Clone)]
pub enum IrQualifier {
    WithinSeconds(f64),
    StartStop { start: String, stop: String },
    RepeatsTimes(i64),
}

#[derive(Debug, Clone)]
pub struct IrPredicate {
    pub target: String,
    pub field: String,
    pub op: IrOp,
    pub value: IrValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Matches,
    IsSubset,
}

#[derive(Debug, Clone)]
pub enum IrValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Hex(String),
    Timestamp(String),
}
