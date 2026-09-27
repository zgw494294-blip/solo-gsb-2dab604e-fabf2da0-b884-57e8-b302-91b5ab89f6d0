"""Tests for POST /reverse (PTR lookups against in-addr.arpa. zones)."""
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ZONE = "in-addr.arpa."
RECORDS = [
    {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "value": "www.example.com"},
    {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "value": "WWW2.Example.COM"},
    # same name repeated: deduped like every other multi-value record
    {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "value": "www2.example.com"},
    # PTR target may live outside the zone
    {"name": "9.113.0.203.in-addr.arpa.", "type": "PTR", "value": "host.elsewhere.example.net"},
    # CNAME inside the reverse zone
    {"name": "2.2.0.192.in-addr.arpa.", "type": "CNAME", "value": "1.2.0.192.in-addr.arpa"},
    {"name": "3.2.0.192.in-addr.arpa.", "type": "CNAME", "value": "ghost.in-addr.arpa"},
    # empty non-terminal: 7.2.0.192.in-addr.arpa exists only as an ancestor
    # of a deeper name, so the address 192.0.2.7 hits an existing empty node.
    {"name": "extra.7.2.0.192.in-addr.arpa.", "type": "A", "value": "198.51.100.7"},
    {"name": "5.2.0.192.in-addr.arpa.", "type": "PTR", "value": "five.example.com"},
]


def post(address, records=RECORDS, zone=ZONE):
    return client.post(
        "/reverse",
        json={"zone": zone, "records": records, "address": address},
    )


# ---------------------------------------------------------------------------
# Query name construction
# ---------------------------------------------------------------------------


def test_query_name_is_reversed_octets_plus_in_addr_arpa():
    r = post("192.0.2.1")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["query"] == "1.2.0.192.in-addr.arpa."
    assert body["address"] == "192.0.2.1"
    assert body["zone"] == "in-addr.arpa."
    assert body["chain"] == ["1.2.0.192.in-addr.arpa."]


def test_zone_apex_without_trailing_dot_is_normalized():
    r = post("192.0.2.1", zone="in-addr.arpa")
    assert r.status_code == 200, r.text
    assert r.json()["zone"] == "in-addr.arpa."


def test_zone_name_is_case_insensitive():
    r = post("192.0.2.1", zone="IN-ADDR.ARPA")
    assert r.status_code == 200, r.text
    assert r.json()["zone"] == "in-addr.arpa."


def test_zero_address_works():
    records = [
        {"name": "0.0.0.0.in-addr.arpa.", "type": "PTR", "value": "root.example.com"}
    ]
    r = post("0.0.0.0", records=records)
    assert r.status_code == 200
    body = r.json()
    assert body["query"] == "0.0.0.0.in-addr.arpa."
    assert body["names"] == ["root.example.com."]


def test_255_address_works():
    records = [
        {"name": "255.255.255.255.in-addr.arpa.", "type": "PTR", "value": "edge.example.com"}
    ]
    r = post("255.255.255.255", records=records)
    assert r.status_code == 200
    assert r.json()["names"] == ["edge.example.com."]


# ---------------------------------------------------------------------------
# PTR answers
# ---------------------------------------------------------------------------


def test_ptr_answer_returns_deduplicated_sorted_hostnames():
    r = post("192.0.2.1")
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["names"] == ["www.example.com.", "www2.example.com."]
    assert body["delegation"] is None
    assert body["error"] is None


def test_ptr_target_outside_zone_is_allowed_and_normalized():
    r = post("203.0.113.9")
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["names"] == ["host.elsewhere.example.net."]


def test_nodata_when_name_exists_without_ptr():
    # an empty non-terminal: the name exists via its descendants only
    r = post("192.0.2.7")
    body = r.json()
    assert body["status"] == "NODATA"
    assert body["names"] == []
    assert body["chain"] == ["7.2.0.192.in-addr.arpa."]


def test_nxdomain_for_missing_name():
    r = post("198.51.100.7")
    body = r.json()
    assert body["status"] == "NXDOMAIN"
    assert body["names"] == []


def test_cname_chain_followed_to_ptr():
    r = post("192.0.2.2")
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["chain"] == [
        "2.2.0.192.in-addr.arpa.",
        "1.2.0.192.in-addr.arpa.",
    ]
    assert body["names"] == ["www.example.com.", "www2.example.com."]


def test_cname_to_missing_name_is_nxdomain():
    r = post("192.0.2.3")
    body = r.json()
    assert body["status"] == "NXDOMAIN"
    assert body["chain"] == [
        "3.2.0.192.in-addr.arpa.",
        "ghost.in-addr.arpa.",
    ]
    assert body["names"] == []


def test_cname_loop_detected():
    records = [
        {"name": "1.10.0.10.in-addr.arpa.", "type": "CNAME", "value": "2.10.0.10.in-addr.arpa"},
        {"name": "2.10.0.10.in-addr.arpa.", "type": "CNAME", "value": "1.10.0.10.in-addr.arpa"},
    ]
    r = post("10.0.10.1", records=records)
    body = r.json()
    assert body["status"] == "CNAME_LOOP"
    assert body["chain"] == [
        "1.10.0.10.in-addr.arpa.",
        "2.10.0.10.in-addr.arpa.",
        "1.10.0.10.in-addr.arpa.",
    ]
    assert body["error"]
    assert body["names"] == []


def test_a_record_only_name_is_nodata_for_ptr():
    records = [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "A", "value": "198.51.100.1"},
    ]
    r = post("192.0.2.1", records=records)
    body = r.json()
    assert body["status"] == "NODATA"
    assert body["names"] == []


# ---------------------------------------------------------------------------
# Wildcards and empty non-terminals (wildcard PTR itself is forbidden)
# ---------------------------------------------------------------------------


def test_wildcard_ptr_is_rejected():
    records = [
        {"name": "*.2.0.192.in-addr.arpa.", "type": "PTR", "value": "x.example.com"},
    ]
    r = post("192.0.2.9", records=records)
    assert r.status_code == 422


def test_wildcard_cname_is_followed():
    records = RECORDS + [
        {"name": "*.9.0.192.in-addr.arpa.", "type": "CNAME",
         "value": "1.2.0.192.in-addr.arpa"},
    ]
    # 192.0.9.7 -> 7.9.0.192: the wildcard *.9.0.192 sits directly below
    # the closest encloser 9.0.192.in-addr.arpa.
    r = post("192.0.9.7", records=records)
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["chain"] == [
        "7.9.0.192.in-addr.arpa.",
        "1.2.0.192.in-addr.arpa.",
    ]
    assert body["names"] == ["www.example.com.", "www2.example.com."]


def test_empty_non_terminal_blocks_upper_wildcard():
    records = [
        {"name": "8.2.0.192.in-addr.arpa.", "type": "PTR", "value": "eight.example.com"},
        # 7.2.0.192.in-addr.arpa exists only as an ancestor (empty node)
        {"name": "extra.7.2.0.192.in-addr.arpa.", "type": "A", "value": "10.0.0.1"},
        # wildcard one label above the empty node; must not reach names under it
        {"name": "*.2.0.192.in-addr.arpa.", "type": "CNAME",
         "value": "8.2.0.192.in-addr.arpa"},
    ]
    # 192.0.2.6 -> 6.2.0.192: closest encloser is the apex in-addr.arpa.
    # (2.0.192 does not exist), so *.2.0.192 matches
    r = post("192.0.2.6", records=records)
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["names"] == ["eight.example.com."]
    # 192.0.2.7 -> 7.2.0.192 exists as an empty node holding no PTR: NODATA,
    # and the wildcard above it must not apply
    r = post("192.0.2.7", records=records)
    body = r.json()
    assert body["status"] == "NODATA"
    assert body["names"] == []
    # a name under a different encloser with no wildcard is NXDOMAIN
    r = post("10.10.10.10", records=records)
    assert r.json()["status"] == "NXDOMAIN"


# ---------------------------------------------------------------------------
# Delegation / REFERRAL
# ---------------------------------------------------------------------------


DELEGATION_RECORDS = [
    {"name": "168.192.in-addr.arpa.", "type": "NS", "value": "ns1.example.net"},
    {"name": "168.192.in-addr.arpa.", "type": "NS", "value": "NS2.Example.NET"},
    # inert PTR below the cut: never authoritative
    {"name": "1.0.168.192.in-addr.arpa.", "type": "PTR", "value": "leak.example.com"},
    {"name": "9.2.0.192.in-addr.arpa.", "type": "PTR", "value": "above.example.com"},
]


def test_referral_at_delegation_point_returns_no_names():
    r = post("192.168.0.0", records=DELEGATION_RECORDS)
    body = r.json()
    assert body["status"] == "REFERRAL"
    assert body["query"] == "0.0.168.192.in-addr.arpa."
    assert body["delegation"] == "168.192.in-addr.arpa."
    assert body["names"] == []
    assert body["nameservers"] == ["ns1.example.net.", "ns2.example.net."]
    assert body["glue"] == []  # ns targets are outside the reverse subtree


def test_referral_inside_delegated_subtree_hides_ptr():
    r = post("192.168.0.1", records=DELEGATION_RECORDS)
    body = r.json()
    assert body["status"] == "REFERRAL"
    assert body["delegation"] == "168.192.in-addr.arpa."
    assert body["chain"] == ["1.0.168.192.in-addr.arpa."]
    assert body["names"] == []


def test_delegation_does_not_affect_names_above_cut():
    r = post("192.0.2.9", records=DELEGATION_RECORDS)
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["names"] == ["above.example.com."]


def test_cname_chain_into_subtree_refers():
    records = DELEGATION_RECORDS + [
        {"name": "5.2.0.192.in-addr.arpa.", "type": "CNAME",
         "value": "1.168.192.in-addr.arpa"},
    ]
    r = post("192.0.2.5", records=records)
    body = r.json()
    assert body["status"] == "REFERRAL"
    assert body["delegation"] == "168.192.in-addr.arpa."
    assert body["chain"] == [
        "5.2.0.192.in-addr.arpa.",
        "1.168.192.in-addr.arpa.",
    ]
    assert body["names"] == []


def test_referral_with_in_subtree_glue():
    records = [
        {"name": "168.192.in-addr.arpa.", "type": "NS", "value": "ns1.168.192.in-addr.arpa"},
        {"name": "ns1.168.192.in-addr.arpa.", "type": "A", "value": "10.0.0.1"},
    ]
    r = post("192.168.2.2", records=records)
    body = r.json()
    assert body["status"] == "REFERRAL"
    assert body["glue"] == [
        {"name": "ns1.168.192.in-addr.arpa.", "type": "A", "addresses": ["10.0.0.1"]}
    ]
    assert body["names"] == []


# ---------------------------------------------------------------------------
# Sub-zones: /8, /16, /24 and the single-address /32 style zone
# ---------------------------------------------------------------------------


SUBZONE_RECORDS = [
    {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "value": "host.example.com"},
]


def test_24_label_zone_answers_inside():
    r = post("192.0.2.1", records=SUBZONE_RECORDS, zone="2.0.192.in-addr.arpa")
    assert r.status_code == 200
    body = r.json()
    assert body["zone"] == "2.0.192.in-addr.arpa."
    assert body["status"] == "NOERROR"
    assert body["names"] == ["host.example.com."]


def test_address_outside_subzone_is_refused():
    r = post("192.0.3.1", records=SUBZONE_RECORDS, zone="2.0.192.in-addr.arpa")
    body = r.json()
    assert body["status"] == "REFUSED"
    assert body["names"] == []
    assert body["query"] == "1.3.0.192.in-addr.arpa."
    assert body["error"]


def test_8_label_zone_answers():
    records = [
        {"name": "4.3.2.10.in-addr.arpa.", "type": "PTR", "value": "deep.example.com"},
    ]
    r = post("10.2.3.4", records=records, zone="10.in-addr.arpa")
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["names"] == ["deep.example.com."]
    r = post("11.2.3.4", records=records, zone="10.in-addr.arpa")
    assert r.json()["status"] == "REFUSED"


def test_four_label_zone_covers_exactly_one_address():
    records = [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "value": "only.example.com"},
    ]
    r = post("192.0.2.1", records=records, zone="1.2.0.192.in-addr.arpa")
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["query"] == body["zone"] == "1.2.0.192.in-addr.arpa."
    assert body["names"] == ["only.example.com."]


# ---------------------------------------------------------------------------
# 422: invalid zones, addresses, records
# ---------------------------------------------------------------------------


def test_forward_zone_rejected():
    records = [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "value": "x.example.com"}
    ]
    r = post("192.0.2.1", records=records, zone="example.com")
    assert r.status_code == 422


def test_reverse_zone_with_non_numeric_label_rejected():
    records = [
        {"name": "1.foo.0.192.in-addr.arpa.", "type": "PTR", "value": "x.example.com"}
    ]
    for zone in (
        "foo.in-addr.arpa",
        "2.foo.192.in-addr.arpa",
        "v6.in-addr.arpa",
    ):
        r = post("192.0.2.1", records=records, zone=zone)
        assert r.status_code == 422, zone


def test_reverse_zone_more_than_four_labels_rejected():
    r = post("192.0.2.1", records=[], zone="1.2.0.192.in-addr.arpa.extra.in-addr.arpa")
    assert r.status_code == 422
    r = post("192.0.2.1", records=[], zone="1.2.3.4.5.in-addr.arpa")
    assert r.status_code == 422


def test_reverse_zone_label_outside_0_255_rejected():
    for zone in ("256.in-addr.arpa", "1.999.192.in-addr.arpa"):
        r = post("192.0.2.1", records=[], zone=zone)
        assert r.status_code == 422, zone


def test_reverse_zone_label_with_leading_zero_rejected():
    r = post("192.0.2.1", records=[], zone="02.0.192.in-addr.arpa")
    assert r.status_code == 422


@pytest.mark.parametrize("address", [
    "256.0.0.1",
    "192.0.2",
    "192.0.2.1.4",
    "192.0.02.1",
    "010.0.0.1",
    "abc.def.ghi.jkl",
    "1.2.3.",
    ".1.2.3.4",
    "::1",
    "",
])
def test_invalid_address_returns_422(address):
    r = post(address)
    assert r.status_code == 422, address


def test_ptr_owner_must_be_full_four_octets():
    for owner in (
        "2.0.192.in-addr.arpa.",   # only three octets (a /24-style name)
        "0.192.in-addr.arpa.",     # two octets
        "1.2.0.192.in-addr.arpa",  # covered, no dot -> sanity baseline
    ):
        records = [{"name": owner.rstrip("."), "type": "PTR", "value": "x.example.com"}]
        r = post("192.0.2.1", records=records)
        if owner.endswith(".in-addr.arpa.") and owner.count(".") < 6:
            assert r.status_code == 422, owner
        else:
            assert r.status_code == 200, owner


def test_ptr_owner_octet_must_be_0_255_without_leading_zero():
    for owner in (
        "1.2.0.256.in-addr.arpa.",
        "1.2.00.192.in-addr.arpa.",
        "01.2.0.192.in-addr.arpa.",
        "x.2.0.192.in-addr.arpa.",
    ):
        records = [{"name": owner, "type": "PTR", "value": "x.example.com"}]
        r = post("192.0.2.1", records=records)
        assert r.status_code == 422, owner


def test_ptr_outside_zone_rejected():
    records = [
        {"name": "1.3.0.192.in-addr.arpa.", "type": "PTR", "value": "x.example.com"},
    ]
    r = post("192.0.2.1", records=records, zone="2.0.192.in-addr.arpa")
    assert r.status_code == 422


def test_ptr_conflicting_with_cname_rejected():
    records = [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "value": "a.example.com"},
        {"name": "1.2.0.192.in-addr.arpa.", "type": "CNAME", "value": "2.2.0.192.in-addr.arpa"},
    ]
    r = post("192.0.2.1", records=records)
    assert r.status_code == 422


def test_ptr_conflicting_with_ns_rejected():
    records = [
        {"name": "2.0.192.in-addr.arpa.", "type": "NS", "value": "ns1.example.net"},
        {"name": "2.0.192.in-addr.arpa.", "type": "PTR", "value": "cut.example.com"},
    ]
    r = post("192.0.2.2", records=records)
    assert r.status_code == 422


def test_ptr_in_forward_zone_rejected():
    r = client.post(
        "/reverse",
        json={
            "zone": "example.com",
            "records": [
                {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
                 "value": "x.example.com"}
            ],
            "address": "192.0.2.1",
        },
    )
    assert r.status_code == 422


def test_ptr_record_in_forward_zone_creation_rejected():
    r = client.post(
        "/zones",
        json={
            "zone": "example.com",
            "records": [
                {"name": "x.example.com", "type": "PTR", "value": "host.example.com"}
            ],
        },
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# A queries keep working inside reverse zones
# ---------------------------------------------------------------------------


def test_a_query_still_resolves_in_reverse_zone():
    records = [
        {"name": "ns1.168.192.in-addr.arpa.", "type": "A", "value": "10.20.30.40"},
    ]
    r = client.post(
        "/resolve",
        json={
            "zone": "168.192.in-addr.arpa",
            "records": records,
            "query": "ns1.168.192.in-addr.arpa",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["addresses"] == ["10.20.30.40"]
    # a PTR-only name is NODATA for an A query
    records.append(
        {"name": "1.0.168.192.in-addr.arpa.", "type": "PTR", "value": "h.example.com"}
    )
    r = client.post(
        "/resolve",
        json={
            "zone": "168.192.in-addr.arpa",
            "records": records,
            "query": "1.0.168.192.in-addr.arpa",
        },
    )
    assert r.json()["status"] == "NODATA"


# ---------------------------------------------------------------------------
# PTR enters snapshots, conditional updates, imports and version archives
# ---------------------------------------------------------------------------


def create_zone(zone, records):
    r = client.post("/zones", json={"zone": zone, "records": records})
    assert r.status_code == 200, r.text
    return r.json()


PTR_RECORD = {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
              "value": "WWW.Example.COM"}


def test_ptr_snapshot_create_normalizes_and_sorts():
    body = create_zone(
        "in-addr.arpa",
        [
            PTR_RECORD,
            {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
             "value": "www.example.com."},
            {"name": "2.2.0.192.in-addr.arpa.", "type": "PTR",
             "value": "alias.example.org"},
        ],
    )
    assert body["zone"] == "in-addr.arpa."
    assert body["records"] == [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "www.example.com."},
        {"name": "2.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "alias.example.org."},
    ]


def test_snapshot_records_drive_reverse_lookup():
    snap = create_zone("in-addr.arpa", [PTR_RECORD])
    r = client.post(
        "/reverse",
        json={"zone": snap["zone"], "records": snap["records"], "address": "192.0.2.1"},
    )
    body = r.json()
    assert body["status"] == "NOERROR"
    assert body["names"] == ["www.example.com."]


def test_ptr_conditional_update_and_version_archive():
    snap = create_zone("in-addr.arpa", [])
    r = client.post(
        f"/zones/{snap['id']}/updates",
        json={
            "expected_version": 0,
            "prerequisites": [
                {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR", "values": []}
            ],
            "operations": [
                {"op": "add", "name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
                 "value": "host.example.com"}
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 1
    assert body["records"] == [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "host.example.com."}
    ]
    # the new version is archived and the diff shows the PTR
    r = client.get(
        f"/zones/{snap['id']}/diff", params={"from_version": 0, "to_version": 1}
    )
    assert r.status_code == 200
    assert r.json()["added"] == [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "host.example.com."}
    ]
    assert r.json()["removed"] == []


def test_ptr_prerequisite_mismatch_conflicts():
    snap = create_zone("in-addr.arpa", [PTR_RECORD])
    r = client.post(
        f"/zones/{snap['id']}/updates",
        json={
            "expected_version": 0,
            "prerequisites": [
                {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
                 "values": ["other.example.net"]}
            ],
            "operations": [
                {"op": "add", "name": "2.2.0.192.in-addr.arpa.", "type": "PTR",
                 "value": "x.example.com"}
            ],
        },
    )
    assert r.status_code == 409


def test_ptr_master_file_import_relative_targets_expand_to_origin():
    r = client.post(
        "/zones/import",
        json={
            "zone": "2.0.192.in-addr.arpa",
            "text": (
                "$TTL 3600\n"
                "$ORIGIN 2.0.192.in-addr.arpa.\n"
                "1 PTR host.example.com.\n"
                "2 PTR alias\n"
                "3 IN PTR outside.example.net.\n"
                "4 300 PTR mail.example.com.\n"
            ),
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["zone"] == "2.0.192.in-addr.arpa."
    assert body["records"] == [
        {"name": "1.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "host.example.com."},
        {"name": "2.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "alias.2.0.192.in-addr.arpa."},
        {"name": "3.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "outside.example.net."},
        {"name": "4.2.0.192.in-addr.arpa.", "type": "PTR",
         "value": "mail.example.com."},
    ]
    # imported snapshot answers /reverse and is archived at version 0
    r = client.post(
        "/reverse",
        json={"zone": body["zone"], "records": body["records"], "address": "192.0.2.1"},
    )
    assert r.json()["names"] == ["host.example.com."]
    r = client.get(
        f"/zones/{body['id']}/diff", params={"from_version": 0, "to_version": 0}
    )
    assert r.status_code == 200


def test_master_file_import_rejects_short_ptr_owner():
    r = client.post(
        "/zones/import",
        json={
            "zone": "in-addr.arpa",
            # "2" expands to 2.in-addr.arpa: only one octet, not a full owner
            "text": "2 PTR host.example.com.\n",
        },
    )
    assert r.status_code == 422
    assert isinstance(r.json()["detail"], str)
