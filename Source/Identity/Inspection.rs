// SPDX-License-Identifier: Apache-2.0
//! Private identity inspection exposes current owned endpoints without credential material.
use super::*;
use crate::home::inspection;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountView {
    pub nickname: String,
    pub revision: u64,
    pub filter_revision: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentEndpoint {
    pub actor: EndpointActor,
    pub nickname: String,
}
pub(super) fn read(db: &Connection, action: &Action) -> Domain<Outcome> {
    inspection::own(action)?;
    if action.operation == Operation::AccountInspect {
        empty(&action.body)?;
        let view = db.query_row(
            "SELECT nickname,revision,filter_revision FROM hrc_accounts WHERE id=?1",
            [action.actor.acting().account.to_string()],
            |r| {
                Ok(AccountView {
                    nickname: r.get(0)?,
                    revision: r.get(1)?,
                    filter_revision: r.get(2)?,
                })
            },
        )?;
        return Ok(Outcome::Result {
            body: value(&view)?,
        });
    }
    let p = inspection::request(action)?;
    let mut stmt=db.prepare("SELECT a.class,e.actor,a.nickname,a.security,a.id||':'||e.endpoint FROM hrc_accounts a JOIN hrc_endpoints e ON e.account=a.id WHERE e.disabled=0 AND a.id||':'||e.endpoint>?1 ORDER BY a.id,e.endpoint LIMIT 512")?;
    let mut rows = stmt.query([p.after.unwrap_or_default()])?;
    let mut result = Vec::new();
    while let Some(r) = rows.next()? {
        let class: AccountClass = decode(&r.get::<_, Vec<u8>>(0)?)?;
        let actor: EndpointActor = decode(&r.get::<_, Vec<u8>>(1)?)?;
        if class
            == (AccountClass::Agent {
                operator: action.actor.acting().account,
            })
            && actor.security_generation == r.get::<_, u64>(3)?
        {
            result.push((
                r.get(4)?,
                AgentEndpoint {
                    actor,
                    nickname: r.get(2)?,
                },
            ));
            if result.len() > usize::from(p.limit) {
                break;
            }
        }
    }
    inspection::page(result, p.limit)
}
