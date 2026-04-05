"""Regression tests for admin user CRUD operations."""

from pathlib import Path

from database import Database


def test_admin_user_crud_flow(tmp_path: Path):
    db_path = tmp_path / "agentic_iam_test.db"
    database = Database(str(db_path))

    username = "crud_admin_test"
    email = "crud_admin_test@example.com"
    password = "TestPass123!"

    created = database.create_user(username=username, email=email, password=password, role="user")
    assert created is True

    users = database.list_users()
    created_user = next((user for user in users if user["username"] == username), None)
    assert created_user is not None

    user_id = created_user["id"]

    assert database.update_user_role(user_id, "operator") is True
    assert database.update_user_status(user_id, "suspended") is True

    updated_user = database.get_user_by_id(user_id)
    assert updated_user is not None
    assert updated_user["role"] == "operator"
    assert updated_user["status"] == "suspended"

    assert database.delete_user(user_id) is True
    assert database.get_user_by_id(user_id) is None
    assert all(user["id"] != user_id for user in database.list_users())
