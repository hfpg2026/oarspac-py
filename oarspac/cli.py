import typer

from .core.main import evaluate_license_compliance


app = typer.Typer()
app.command()(evaluate_license_compliance)

if __name__ == "__main__":
    app()
