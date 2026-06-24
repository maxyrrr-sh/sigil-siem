//! A small **pipe-DSL** that lowers to SQL over the `events` table (DESIGN
//! §17, ADR-1: both SQL and a pipe-DSL over one engine). It is intentionally a
//! thin sugar layer — every query is translated to SQL and run by DataFusion.
//!
//! Grammar (stages separated by `|`):
//!
//! ```text
//! search <terms...>                  → WHERE message ILIKE '%terms%'
//! where <col> <op> <value>           → WHERE col op value   (op: = != > < >= <= contains)
//! stats count() [as <name>] [by a,b] → SELECT a,b,count(*) AS name GROUP BY a,b
//! fields <a,b,c>                     → SELECT a,b,c
//! sort <col> [asc|desc]              → ORDER BY col [DESC]
//! head <n> | limit <n>               → LIMIT n
//! ```

use sigil_core::{Error, Result};

#[derive(Default)]
struct Builder {
    select: Option<Vec<String>>,
    aggregates: Vec<String>,
    group_by: Vec<String>,
    wheres: Vec<String>,
    order_by: Option<String>,
    limit: Option<usize>,
}

impl Builder {
    fn render(&self) -> String {
        let select = if !self.aggregates.is_empty() {
            let mut cols = self.group_by.clone();
            cols.extend(self.aggregates.clone());
            cols.join(", ")
        } else if let Some(fields) = &self.select {
            fields.join(", ")
        } else {
            "*".to_string()
        };

        let mut sql = format!("SELECT {select} FROM events");
        if !self.wheres.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&self.wheres.join(" AND "));
        }
        if !self.group_by.is_empty() {
            sql.push_str(" GROUP BY ");
            sql.push_str(&self.group_by.join(", "));
        }
        if let Some(ob) = &self.order_by {
            sql.push_str(" ORDER BY ");
            sql.push_str(ob);
        }
        if let Some(n) = self.limit {
            sql.push_str(&format!(" LIMIT {n}"));
        }
        sql
    }
}

/// Lower a pipe-DSL query into a SQL string.
pub fn lower(dsl: &str) -> Result<String> {
    let mut b = Builder::default();
    for raw in dsl.split('|') {
        let stage = raw.trim();
        if stage.is_empty() {
            continue;
        }
        let (cmd, rest) = split_first(stage);
        match cmd.to_ascii_lowercase().as_str() {
            "search" => {
                let term = rest.trim();
                if !term.is_empty() {
                    b.wheres.push(format!("message ILIKE '%{}%'", escape(term)));
                }
            }
            "where" => b.wheres.push(parse_where(rest)?),
            "stats" => parse_stats(rest, &mut b)?,
            "fields" => {
                b.select = Some(
                    rest.split(',')
                        .map(|s| ident(s.trim()))
                        .collect::<Result<_>>()?,
                );
            }
            "sort" => {
                let mut it = rest.split_whitespace();
                let col = ident(it.next().unwrap_or(""))?;
                let dir = match it.next().map(|d| d.to_ascii_lowercase()) {
                    Some(d) if d == "desc" => " DESC",
                    _ => "",
                };
                b.order_by = Some(format!("{col}{dir}"));
            }
            "head" | "limit" => {
                b.limit = Some(rest.trim().parse().map_err(|_| {
                    Error::Parse(format!("`{cmd}` expects a number, got `{}`", rest.trim()))
                })?);
            }
            other => return Err(Error::Parse(format!("unknown DSL command `{other}`"))),
        }
    }
    Ok(b.render())
}

fn parse_where(rest: &str) -> Result<String> {
    let toks: Vec<&str> = rest.split_whitespace().collect();
    if toks.len() < 3 {
        return Err(Error::Parse(format!(
            "`where` expects `<col> <op> <value>`, got `{rest}`"
        )));
    }
    let col = ident(toks[0])?;
    let op = toks[1];
    let value = toks[2..].join(" ");
    let sql_op = match op {
        "=" | "==" => "=",
        "!=" | "<>" => "!=",
        ">" => ">",
        "<" => "<",
        ">=" => ">=",
        "<=" => "<=",
        "contains" => {
            return Ok(format!("{col} ILIKE '%{}%'", escape(&unquote(&value))));
        }
        other => {
            return Err(Error::Parse(format!(
                "unknown operator `{other}` in `where`"
            )))
        }
    };
    Ok(format!("{col} {sql_op} {}", literal(&value)))
}

fn parse_stats(rest: &str, b: &mut Builder) -> Result<()> {
    // forms: "count()", "count() as n", "count() by host", "count() as n by host, app"
    let lower = rest.to_ascii_lowercase();
    if !lower.trim_start().starts_with("count()") {
        return Err(Error::Parse(format!(
            "only `count()` is supported in `stats`, got `{rest}`"
        )));
    }
    let after = rest.trim_start()[7..].trim(); // after "count()"
    let mut alias = "count".to_string();
    let by_part = if let Some(stripped) = after
        .strip_prefix("as ")
        .or_else(|| after.strip_prefix("AS "))
    {
        let mut it = stripped.splitn(2, " by ");
        alias = ident(it.next().unwrap_or("count").trim())?;
        it.next().unwrap_or("").trim()
    } else if let Some(idx) = after.find("by ") {
        after[idx + 3..].trim()
    } else {
        ""
    };
    b.aggregates.push(format!("count(*) AS {alias}"));
    if !by_part.is_empty() {
        b.group_by = by_part
            .split(',')
            .map(|s| ident(s.trim()))
            .collect::<Result<_>>()?;
    }
    Ok(())
}

fn split_first(s: &str) -> (&str, &str) {
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

/// Validate an identifier (column name) to keep it injection-safe.
fn ident(s: &str) -> Result<String> {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(s.to_string())
    } else {
        Err(Error::Parse(format!("invalid identifier `{s}`")))
    }
}

/// Render a value as a SQL literal: bare if numeric, single-quoted otherwise.
fn literal(value: &str) -> String {
    let v = unquote(value);
    if v.parse::<f64>().is_ok() {
        v
    } else {
        format!("'{}'", escape(&v))
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn escape(s: &str) -> String {
    s.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_group_by() {
        let sql = lower("stats count() by host").unwrap();
        assert_eq!(
            sql,
            "SELECT host, count(*) AS count FROM events GROUP BY host"
        );
    }

    #[test]
    fn full_pipeline() {
        let sql =
            lower("search failed | where severity = high | stats count() as n by host | sort n desc | head 5")
                .unwrap();
        assert_eq!(
            sql,
            "SELECT host, count(*) AS n FROM events WHERE message ILIKE '%failed%' AND severity = 'high' GROUP BY host ORDER BY n DESC LIMIT 5"
        );
    }

    #[test]
    fn where_numeric_stays_bare() {
        let sql = lower("where severity_id >= 4").unwrap();
        assert_eq!(sql, "SELECT * FROM events WHERE severity_id >= 4");
    }

    #[test]
    fn contains_becomes_ilike() {
        let sql = lower("where message contains shadow").unwrap();
        assert_eq!(sql, "SELECT * FROM events WHERE message ILIKE '%shadow%'");
    }

    #[test]
    fn rejects_bad_identifier_injection() {
        assert!(lower("where host; drop = x").is_err());
        assert!(lower("fields a, b; DROP TABLE events").is_err());
    }
}
