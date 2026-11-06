"""The HTML list views page their results and show a friendly empty state."""

from models import Application


def test_applications_index_pages_its_results(
    client, app, db, make_user, make_application, login
):
    owner = make_user("owner1")
    app.config["PER_PAGE"] = 2
    for index in range(5):
        make_application(owner, name=f"App {index}")
    login("owner1")

    first = client.get("/applications/")
    body = first.get_data(as_text=True)

    assert first.status_code == 200
    assert "Page 1 of 3" in body
    assert "record(s)" in body
    assert "page=2" in body

    second = client.get("/applications/?page=2").get_data(as_text=True)
    assert "Page 2 of 3" in second


def test_pagination_links_keep_the_search_term(
    client, app, db, make_user, make_application, login
):
    owner = make_user("owner1")
    app.config["PER_PAGE"] = 1
    for index in range(3):
        make_application(owner, name=f"Target {index}")
    login("owner1")

    body = client.get("/applications/?q=target").get_data(as_text=True)

    assert "q=target" in body
    assert "page=2" in body


def test_an_empty_list_shows_a_message_not_a_broken_page(client, make_user, login):
    make_user("owner1")
    login("owner1")

    body = client.get("/applications/").get_data(as_text=True)

    assert "No applications found." in body
    assert "0 record(s)" in body


def test_the_database_is_scoped_to_the_visible_records(
    client, app, db, make_user, make_application, login
):
    owner = make_user("owner1")
    other = make_user("other1")
    app.config["PER_PAGE"] = 2
    for index in range(3):
        make_application(owner, name=f"Mine {index}")
    make_application(other, name="Not mine")
    login("owner1")

    body = client.get("/applications/").get_data(as_text=True)

    assert db.session.query(Application).count() == 4
    assert "Page 1 of 2" in body
    assert "3 record(s)" in body
    assert "Not mine" not in body
