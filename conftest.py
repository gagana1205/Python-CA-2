"""Shared test fixtures for pytest."""
import pytest
from app import create_app, db
from app.models import User


@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(app, client):
    with app.app_context():
        user = User(username='testuser', email='test@example.com', role='analyst')
        user.set_password('Test@1234')
        db.session.add(user)
        db.session.commit()

        client.post('/login', data={
            'username': 'testuser',
            'password': 'Test@1234'
        }, follow_redirects=True)

    return client
