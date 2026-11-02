// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::protocol::{Id, NetworkId};

fn account(n: u8) -> AccountId {
    AccountId {
        origin: NetworkId {
            network: Id::from_bytes([1; 32]),
            incarnation: Id::from_bytes([2; 32]),
        },
        local: Id::from_bytes([n; 32]),
    }
}

#[test]
fn authority_withdrawal_barrier_is_atomic_and_covers_represented_and_operator_accounts() {
    let mut db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE hrc_rooms(id TEXT PRIMARY KEY,revision INTEGER NOT NULL);")
        .unwrap();
    db.execute_batch(schema::SQL).unwrap();
    for (room, acting, represented, operator) in [
        ("first", account(3), account(4), account(5)),
        ("second", account(6), account(6), account(7)),
    ] {
        db.execute("INSERT INTO hrc_rooms VALUES(?1,1)", [room])
            .unwrap();
        db.execute(
            "INSERT INTO hrc_encrypted_rooms(room,barrier) VALUES(?1,0)",
            [room],
        )
        .unwrap();
        db.execute(
            "INSERT INTO hrc_encrypted_roster VALUES(?1,'endpoint',?2,?3,?4,NULL,X'',X'',X'',NULL)",
            params![
                room,
                acting.to_string(),
                represented.to_string(),
                operator.to_string()
            ],
        )
        .unwrap();
    }
    {
        let tx = db.transaction().unwrap();
        invalidate_accounts(&tx, &[account(4), account(5)]).unwrap();
        assert_eq!(
            tx.query_row(
                "SELECT barrier FROM hrc_encrypted_rooms WHERE room='first'",
                [],
                |r| r.get::<_, u8>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            tx.query_row("SELECT revision FROM hrc_rooms WHERE id='first'", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            2
        );
        // A rejected identity transition must not leave an independently committed barrier.
    }
    assert_eq!(
        db.query_row("SELECT sum(barrier) FROM hrc_encrypted_rooms", [], |r| r
            .get::<_, u8>(0))
            .unwrap(),
        0
    );
    let tx = db.transaction().unwrap();
    invalidate_accounts(&tx, &[account(5), account(5)]).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        db.query_row(
            "SELECT barrier FROM hrc_encrypted_rooms WHERE room='first'",
            [],
            |r| r.get::<_, u8>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT barrier FROM hrc_encrypted_rooms WHERE room='second'",
            [],
            |r| r.get::<_, u8>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT revision FROM hrc_rooms WHERE id='first'", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM hrc_encrypted_roster", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        2
    );
}
