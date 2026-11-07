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
