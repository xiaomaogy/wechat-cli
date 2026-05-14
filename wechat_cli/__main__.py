"""Module-entry shim so `python -m wechat_cli ...` works in addition to the
`wechat-cli` console_script. ChatLens uses this in its bundled .app — it
ships the wechat_cli package inside the bundle's site-packages and invokes
it via `Contents/MacOS/python -m wechat_cli`, sidestepping the need to
install/PATH the console_script separately."""
from .main import cli

if __name__ == "__main__":
    cli()
