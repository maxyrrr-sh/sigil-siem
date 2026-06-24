//! Semantic triplet extraction (DESIGN §9.2): reduce an event to a
//! `(subject, action, object)` atom. These are the semantic units that become
//! provenance-graph edges and feed embeddings.

use sigil_core::{EntityRef, Event};

/// A `(subject, action, object)` semantic atom for one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triplet {
    pub subject: Option<EntityRef>,
    pub action: String,
    pub object: Option<EntityRef>,
}

/// Extract the triplet for an event. Subject is the actor (falling back to the
/// host), object is the target, and the action is derived from the OCSF class.
pub fn extract_triplet(event: &Event) -> Triplet {
    let subject = event.actor.clone().or_else(|| event.host.clone());
    Triplet {
        subject,
        action: action_for(event),
        object: event.target.clone(),
    }
}

fn action_for(event: &Event) -> String {
    use sigil_core::OcsfClass::*;
    match event.ocsf_class {
        Authentication => "authenticate",
        ProcessActivity => "execute",
        FileSystemActivity => "access",
        NetworkActivity => "connect",
        HttpActivity => "request",
        ApiActivity => "invoke",
        Other(_) => "event",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::OcsfClass;

    #[test]
    fn extracts_subject_action_object() {
        let mut e = Event::new("acme");
        e.ocsf_class = OcsfClass::FileSystemActivity;
        e.actor = Some(EntityRef::new("process", "cat"));
        e.target = Some(EntityRef::new("file", "/etc/shadow"));
        let t = extract_triplet(&e);
        assert_eq!(t.subject.unwrap().id, "cat");
        assert_eq!(t.action, "access");
        assert_eq!(t.object.unwrap().id, "/etc/shadow");
    }

    #[test]
    fn falls_back_to_host_as_subject() {
        let mut e = Event::new("acme");
        e.host = Some(EntityRef::new("host", "web01"));
        let t = extract_triplet(&e);
        assert_eq!(t.subject.unwrap().id, "web01");
    }
}
