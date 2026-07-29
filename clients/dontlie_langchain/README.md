# dontlie-langchain

Drop-in instrumentation for LangChain / LangGraph LLMs.

```python
from dontlie_langchain import DontlieCallback
from langchain.chat_models import ChatOpenAI

callback = DontlieCallback()
chain = ChatOpenAI(model="gpt-4o-mini", callbacks=[callback])
chain.invoke("What's the capital of France?")
# Receipt written to your local vault.
```

## What it does

For every chat completion, Don't-Lie:

1. Captures the exact prompt and response bytes.
2. Writes a signed, hash-linked receipt to the local vault.
3. Optionally redacts secrets (ANTHROPIC_API_KEY, OPENAI_API_KEY, EMAIL,
   SSN, CREDIT_CARD, PHONE, JWT, private keys, RFC 7617 basic auth).
4. Falls back to a no-op if the `langchain-core` package is missing —
   useful for environments that just want the callback class.

## Install

```sh
pip install dontlie-langchain[langchain]
```

## Configuration

| Env | Default | Purpose |
|---|---|---|
| `DONTLIE_LANGCHAIN_SYNC` | `async` | `async` / `thread` / `inline` |
| `DONTLIE_LANGCHAIN_TAGS` | `[]` | JSON list of tags to attach to every receipt |
| `DONTLIE_REDACTION_POLICY` | `default` | `off` / `default` / `strict` |

## License

MIT.
