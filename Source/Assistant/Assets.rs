// SPDX-License-Identifier: Apache-2.0
//! Provider files are rendered from embedded product assets, never from private state.
use super::{Provider, Scope};
use std::collections::BTreeMap;

pub const COMPATIBILITY: &str = include_str!("../../Harness/compatibility.json");
const SKILLS: [(&str, &str); 5] = [
    (
        "hrc-setup",
        include_str!("../../Harness/skills/hrc-setup/SKILL.md"),
    ),
    (
        "hrc-operations",
        include_str!("../../Harness/skills/hrc-operations/SKILL.md"),
    ),
    (
        "hrc-models",
        include_str!("../../Harness/skills/hrc-models/SKILL.md"),
    ),
    (
        "hrc-security",
        include_str!("../../Harness/skills/hrc-security/SKILL.md"),
    ),
    (
        "hrc-recovery",
        include_str!("../../Harness/skills/hrc-recovery/SKILL.md"),
    ),
];
const ROLES: [(&str, &str, &str); 3] = [
    (
        "hrc-observer",
        "Inspect supplied HRC evidence without changing state.",
        include_str!("../../Harness/roles/hrc-observer.md"),
    ),
    (
        "hrc-local-operator",
        "Perform authorised HRC setup and operations on a selected local host.",
        include_str!("../../Harness/roles/hrc-local-operator.md"),
    ),
    (
        "hrc-remote-operator",
        "Perform authorised HRC operations on an explicitly selected remote host.",
        include_str!("../../Harness/roles/hrc-remote-operator.md"),
    ),
];

pub fn files(provider: Provider, scope: Scope) -> BTreeMap<String, Vec<u8>> {
    let (skills, agents) = provider.directories(scope);
    let mut files = BTreeMap::new();
    for (name, body) in SKILLS {
        files.insert(
            format!("{skills}/{name}/SKILL.md"),
            body.as_bytes().to_vec(),
        );
    }
    files.insert(
        format!("{skills}/hrc-setup/references/Contract.md"),
        include_bytes!("../../Harness/skills/hrc-setup/references/Contract.md").to_vec(),
    );
    for (name, description, body) in ROLES {
        let references = SKILLS
            .iter()
            .map(|(skill, _)| format!("- [{skill}](../../{skills}/{skill}/SKILL.md)\n"))
            .collect::<String>();
        let body = format!("{body}\n## Installed skills\n\n{references}");
        let (extension, content) = role(provider, name, description, &body);
        files.insert(format!("{agents}/{name}.{extension}"), content.into_bytes());
    }
    let support = format!(".hrc-harness/providers/{}", provider.name());
    files.insert(
        format!("{support}/README.md"),
        include_bytes!("../../Harness/README.md").to_vec(),
    );
    files.insert(
        format!("{support}/compatibility.json"),
        COMPATIBILITY.as_bytes().to_vec(),
    );
    files.insert(
        format!("{support}/LICENSE"),
        include_bytes!("../../LICENSE").to_vec(),
    );
    files
}

fn quote(value: &str) -> String {
    // JSON quoted strings also provide valid TOML basic strings and YAML scalars.
    serde_json::to_string(value).expect("String serialization is infallible")
}

fn role(provider: Provider, name: &str, description: &str, body: &str) -> (&'static str, String) {
    let observer = name == "hrc-observer";
    if provider == Provider::Codex {
        let mut content = format!(
            "name = {}\ndescription = {}\ndeveloper_instructions = {}\n",
            quote(name),
            quote(description),
            quote(body)
        );
        if observer {
            content.push_str("\n[features]\nshell_tool = false\napps = false\nplugins = false\nmemories = false\nrequest_permissions_tool = false\n");
        }
        return ("toml", content);
    }
    let mut content = format!(
        "---\nname: {}\ndescription: {}\n",
        quote(name),
        quote(description)
    );
    if provider == Provider::Gemini {
        content.push_str("kind: local\n");
    }
    if observer {
        content.push_str(match provider {
            Provider::Claude => "tools: [Read, Grep, Glob]\n",
            Provider::Gemini => "tools: [read_file, grep_search]\n",
            Provider::Copilot => "tools: [read, search]\n",
            Provider::Cursor => "readonly: true\n",
            Provider::Codex => unreachable!(),
        });
    }
    content.push_str("---\n\n");
    content.push_str(body);
    (
        if provider == Provider::Copilot {
            "agent.md"
        } else {
            "md"
        },
        content,
    )
}
