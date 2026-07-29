"""dontlie_agent — wrap an agent runtime in a don'tlie signed proxy.

Two ways to use it:

    # 1. Subprocess: spawn an agent under a managed proxy
    dontlie-agent run --port 8080 -- claude-code --verbose
    dontlie-agent run --port 8080 -- hermes chat

    # 2. One-line, in-process (any agent framework)
    import dontlie_agent
    dontlie_agent.install()        # patch every detected SDK
    from openai import OpenAI
    OpenAI().chat.completions.create(...)   # ← this is now signed

    with dontlie_agent.installed():         # clean teardown
        ...

    @dontlie_agent.sign
    def my_step(prompt: str) -> str:
        from openai import OpenAI
        return OpenAI().chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
        ).choices[0].message.content

For the env-var approach (no in-process patching):
    dontlie-agent env --port 8080          # prints export lines
    dontlie-agent wrap --port 8080 -- X    # exec X with env exported
    dontlie-agent start-proxy --port 8080  # just the proxy, foreground
"""
from . import cli
from .auto import InstallHandle, install, installed, sign

__all__ = [
    "InstallHandle",
    "cli",
    "install",
    "installed",
    "sign",
]
