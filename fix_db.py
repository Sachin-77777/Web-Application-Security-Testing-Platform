from app import create_app
from extensions import db

app = create_app()

with app.app_context():
    db.session.execute(
        db.text("""
        ALTER TABLE users
        ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT TRUE
        """)
    )
    db.session.commit()

print("Column added successfully")