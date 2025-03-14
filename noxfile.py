import nox


@nox.session
def tests(session):
    session.install("pytest")
    session.run("pytest")


@nox.session
def lint(session):
    session.install("black")
    session.run("black", ".")
