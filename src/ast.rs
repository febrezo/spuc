#[derive(Debug, Clone)]
pub struct Pattern {
    pub expr: Expr,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Comparison(Comparison),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    FollowedBy(Vec<Expr>),
    Qualified(Box<Expr>, Vec<ObservationQualifier>),
}

#[derive(Debug, Clone)]
pub enum ObservationQualifier {
    WithinSeconds(f64),
    StartStop { start: String, stop: String },
    RepeatsTimes(i64),
}

#[derive(Debug, Clone)]
pub struct Comparison {
    pub object_type: String,
    pub field: String,
    pub op: CompareOp,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Like,
    Matches,
    IsSubset,
}

#[derive(Debug, Clone)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
    Hex(String),
    Timestamp(String),
}
