import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import get_database

pw = 'ECcd+QevJPSze$-tJdv^'
print('Checking admin auth...')
db = get_database()
user = db.authenticate_user('admin', pw)
if user:
    print('AUTH OK')
    print('User row:', user)
else:
    print('AUTH FAILED')
