from database import get_database
import sys
from pathlib import Path

# Ensure project root is on sys.path when run from scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    db = get_database()
    admin_id = 1
    new_pwd = "test-admin-pwd"
    ok = db.change_password(admin_id, new_pwd)
    print("changed:", ok)


if __name__ == '__main__':
    main()
