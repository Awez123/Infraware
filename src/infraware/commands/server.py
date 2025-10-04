import typer
import uvicorn
from typing_extensions import Annotated

app = typer.Typer(help="Manage the InfraWare web server.")

@app.command("start")
def start_server(
    host: Annotated[str, typer.Option(help="The host to bind the server to.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="The port to run the server on.")] = 8000
):
    """
    Starts the InfraWare web server.
    """
    typer.echo(f"Starting InfraWare server at http://{host}:{port}")
    # We tell uvicorn where to find our FastAPI 'app' object
    uvicorn.run("infraware.server.main:app", host=host, port=port, reload=True)
