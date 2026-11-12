"""Smoke tests for the API. Need a database: DATABASE_URL (Postgres in CI) or the SQLite fallback."""
import random

import pytest

from config import vuln_app


@pytest.fixture(scope="module")
def client():
    # /createdb gives each seed user a book titled "bookTitle<randrange(100)>" and
    # book_title is unique, so ~3% of runs collide and return 500 (upstream bug).
    # A fixed seed makes the seed data deterministic: 49, 97, 53.
    random.seed(0)
    c = vuln_app.app.test_client()
    r = c.get("/createdb")
    assert r.status_code == 200
    return c


def login(client, username, password):
    r = client.post("/users/v1/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return r.get_json()


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "VAmPI" in r.get_json()["message"]


def test_list_users(client):
    r = client.get("/users/v1")
    assert r.status_code == 200
    names = [u["username"] for u in r.get_json()["users"]]
    assert "admin" in names


def test_login_and_me(client):
    token = login(client, "name1", "pass1")["auth_token"]
    r = client.get("/me", headers={"Authorization": "Bearer " + token})
    assert r.status_code == 200
    assert r.get_json()["data"]["username"] == "name1"


def test_wrong_password_rejected(client):
    body = login(client, "name1", "wrong")
    assert body["status"] == "fail"


def test_books_listed(client):
    r = client.get("/books/v1")
    assert r.status_code == 200
    assert len(r.get_json()["Books"]) >= 3


def test_book_requires_token(client):
    r = client.get("/books/v1/anything")
    assert r.status_code == 401


# --- Regression tests for fixed findings (NOTE.md, Task 5) --------------------

def test_user_lookup_still_works(client):
    r = client.get("/users/v1/name1")
    assert r.status_code == 200
    assert '"username": "name1"' in r.get_data(as_text=True)


@pytest.mark.parametrize("payload", ["name1' OR '1'='1", "'", "x' UNION SELECT 1,2,3,4,5--"])
def test_user_lookup_is_not_injectable(client, payload):
    # PT-01: these used to change the statement (always-true, syntax error -> 500).
    # As a bound parameter they are just a username nobody has.
    r = client.get("/users/v1/" + payload)
    assert r.status_code == 404


def test_email_check_does_not_backtrack(client):
    # PT-11: 29 characters took ~10 s with the old pattern and grew exponentially.
    import time
    token = login(client, "name1", "pass1")["auth_token"]
    headers = {"Authorization": "Bearer " + token}
    start = time.monotonic()
    r = client.put("/users/v1/name1/email", json={"email": "a" * 60 + "!"}, headers=headers)
    assert time.monotonic() - start < 1
    assert r.status_code == 400
    r = client.put("/users/v1/name1/email", json={"email": "name1.new@mail.example.org"}, headers=headers)
    assert r.status_code == 204


def test_password_change_is_limited_to_the_owner_or_an_admin(client):
    # PT-03: name1 used to be able to change name2's password.
    headers = {"Authorization": "Bearer " + login(client, "name1", "pass1")["auth_token"]}
    r = client.put("/users/v1/name2/password", json={"password": "hijacked"}, headers=headers)
    assert r.status_code == 403
    assert login(client, "name2", "pass2")["status"] == "success"      # unchanged

    r = client.put("/users/v1/name1/password", json={"password": "pass1"}, headers=headers)
    assert r.status_code == 204                                         # own password

    admin = {"Authorization": "Bearer " + login(client, "admin", "pass1")["auth_token"]}
    r = client.put("/users/v1/name2/password", json={"password": "pass2"}, headers=admin)
    assert r.status_code == 204                                         # an admin may
