//! The Sigma `condition` mini-language: a boolean expression over selection
//! names with `and`/`or`/`not`, parentheses, and the `N of <pattern>`
//! quantifiers (DESIGN §8). Supported subset:
//!
//! * `selection`, `selection and not filter`, `(a or b) and c`
//! * `all of them`, `1 of them`, `2 of them`
//! * `all of selection*`, `1 of filter*`

use std::collections::HashMap;

use sigil_core::{Error, Result};

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    And,
    Or,
    Not,
    Of,
    Them,
    All,
    Num(usize),
    Ident(String),
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Tok>> {
    let mut toks = Vec::new();
    // Make parens whitespace-separable, then split.
    let spaced = input.replace('(', " ( ").replace(')', " ) ");
    for word in spaced.split_whitespace() {
        let tok = match word.to_ascii_lowercase().as_str() {
            "and" => Tok::And,
            "or" => Tok::Or,
            "not" => Tok::Not,
            "of" => Tok::Of,
            "them" => Tok::Them,
            "all" => Tok::All,
            "(" => Tok::LParen,
            ")" => Tok::RParen,
            _ => {
                if let Ok(n) = word.parse::<usize>() {
                    Tok::Num(n)
                } else {
                    Tok::Ident(word.to_string())
                }
            }
        };
        toks.push(tok);
    }
    if toks.is_empty() {
        return Err(Error::Config("empty condition".into()));
    }
    Ok(toks)
}

/// Parsed condition expression.
#[derive(Debug, Clone)]
pub enum Expr {
    Ref(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Quant {
        at_least: Option<usize>,
        target: Target,
    },
}

/// Target of a quantifier: all selections (`them`) or a name/prefix pattern.
#[derive(Debug, Clone)]
pub enum Target {
    Them,
    /// `selection*` → prefix; `selection` → exact.
    Pattern(String),
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn expect(&mut self, t: Tok) -> Result<()> {
        if self.next().as_ref() == Some(&t) {
            Ok(())
        } else {
            Err(Error::Config(format!("condition: expected {t:?}")))
        }
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            let rhs = self.parse_and()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let rhs = self.parse_not()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.next() {
            Some(Tok::LParen) => {
                let e = self.parse_or()?;
                self.expect(Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::All) => {
                self.expect(Tok::Of)?;
                Ok(Expr::Quant {
                    at_least: None,
                    target: self.parse_target()?,
                })
            }
            Some(Tok::Num(n)) => {
                self.expect(Tok::Of)?;
                Ok(Expr::Quant {
                    at_least: Some(n),
                    target: self.parse_target()?,
                })
            }
            Some(Tok::Ident(name)) => Ok(Expr::Ref(name)),
            other => Err(Error::Config(format!("condition: unexpected {other:?}"))),
        }
    }

    fn parse_target(&mut self) -> Result<Target> {
        match self.next() {
            Some(Tok::Them) => Ok(Target::Them),
            Some(Tok::Ident(p)) => Ok(Target::Pattern(p)),
            other => Err(Error::Config(format!(
                "condition: expected target, got {other:?}"
            ))),
        }
    }
}

/// Parse a condition string into an [`Expr`].
pub fn parse(input: &str) -> Result<Expr> {
    let toks = tokenize(input)?;
    let mut p = Parser { toks, pos: 0 };
    let expr = p.parse_or()?;
    if p.pos != p.toks.len() {
        return Err(Error::Config(format!(
            "condition: trailing tokens in `{input}`"
        )));
    }
    Ok(expr)
}

impl Target {
    fn select<'a>(&self, names: &'a [String]) -> Vec<&'a String> {
        match self {
            Target::Them => names.iter().collect(),
            Target::Pattern(p) => {
                if let Some(prefix) = p.strip_suffix('*') {
                    names.iter().filter(|n| n.starts_with(prefix)).collect()
                } else {
                    names.iter().filter(|n| n.as_str() == p).collect()
                }
            }
        }
    }
}

/// Evaluate the expression given per-selection results and the set of all
/// selection names defined in the rule.
pub fn eval(expr: &Expr, results: &HashMap<String, bool>, names: &[String]) -> bool {
    match expr {
        Expr::Ref(n) => *results.get(n).unwrap_or(&false),
        Expr::Not(e) => !eval(e, results, names),
        Expr::And(a, b) => eval(a, results, names) && eval(b, results, names),
        Expr::Or(a, b) => eval(a, results, names) || eval(b, results, names),
        Expr::Quant { at_least, target } => {
            let selected = target.select(names);
            let hits = selected
                .iter()
                .filter(|n| *results.get(**n).unwrap_or(&false))
                .count();
            match at_least {
                None => !selected.is_empty() && hits == selected.len(), // "all of"
                Some(k) => hits >= *k,                                  // "N of"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, bool)]) -> HashMap<String, bool> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn and_not() {
        let e = parse("selection and not filter").unwrap();
        let names = vec!["selection".to_string(), "filter".to_string()];
        assert!(eval(
            &e,
            &m(&[("selection", true), ("filter", false)]),
            &names
        ));
        assert!(!eval(
            &e,
            &m(&[("selection", true), ("filter", true)]),
            &names
        ));
    }

    #[test]
    fn one_of_them() {
        let e = parse("1 of them").unwrap();
        let names = vec!["a".to_string(), "b".to_string()];
        assert!(eval(&e, &m(&[("a", false), ("b", true)]), &names));
        assert!(!eval(&e, &m(&[("a", false), ("b", false)]), &names));
    }

    #[test]
    fn all_of_prefix() {
        let e = parse("all of sel*").unwrap();
        let names = vec!["sel1".to_string(), "sel2".to_string(), "other".to_string()];
        assert!(eval(
            &e,
            &m(&[("sel1", true), ("sel2", true), ("other", false)]),
            &names
        ));
        assert!(!eval(&e, &m(&[("sel1", true), ("sel2", false)]), &names));
    }

    #[test]
    fn precedence_or_below_and() {
        // a or b and c  ==  a or (b and c)
        let e = parse("a or b and c").unwrap();
        let names = vec!["a".into(), "b".into(), "c".into()];
        assert!(eval(
            &e,
            &m(&[("a", true), ("b", false), ("c", false)]),
            &names
        ));
        assert!(!eval(
            &e,
            &m(&[("a", false), ("b", true), ("c", false)]),
            &names
        ));
    }

    #[test]
    fn parens() {
        let e = parse("(a or b) and c").unwrap();
        let names = vec!["a".into(), "b".into(), "c".into()];
        assert!(eval(
            &e,
            &m(&[("a", true), ("b", false), ("c", true)]),
            &names
        ));
        assert!(!eval(
            &e,
            &m(&[("a", true), ("b", false), ("c", false)]),
            &names
        ));
    }
}
