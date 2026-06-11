# Models Configuration

Pi loads available models from a built-in registry and an optional user-defined `models.json`.

## Location

| Path | Description |
|------|-------------|
| `~/.pi/agent/models.json` | User-defined model overrides and custom providers |

## Schema

The root object contains a `providers` map.

```json
{
  "providers": {
    "openai": { ... },
    "anthropic": { ... },
    "ollama": { ... }
  }
}
```

### Provider Config

| Field | Type | Description |
|-------|------|-------------|
| `baseUrl` | string | Base API URL (e.g. `https://api.openai.com/v1`) |
| `api` | string | Protocol adapter (e.g. `openai-completions`, `openai-responses`, `anthropic-messages`, `google-generative-ai`, `google-vertex`) |
| `apiKey` | string | API key, env var name, or shell command (see Secret Resolution) |
| `models` | object[] | List of models. If omitted, provider settings override built-in config for that provider. |
| `headers` | object | Custom HTTP headers |
| `authHeader` | boolean | If true, sends key in `Authorization: Bearer <key>` |
| `compat` | object | Compatibility flags |

If `models` is provided, built-in models for that provider are replaced with the list in `models.json`.

### Model Config

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Model ID sent to API |
| `name` | string | Display name |
| `contextWindow` | number | Context window size in tokens |
| `maxTokens` | number | Max output tokens |
| `reasoning` | boolean | True if model supports extended thinking |
| `input` | string[] | `["text", "image"]` |
| `cost` | object | Cost per million tokens |

### Compatibility Flags (`compat`)

| Field | Description |
|-------|-------------|
| `supportsStore` | Enable OpenAI `store` parameter (where supported) |
| `supportsDeveloperRole` | Use `developer` role instead of `system` (OpenAI o1/o3) |
| `supportsReasoningEffort` | Send `reasoning_effort` param (OpenAI) |
| `supportsUsageInStreaming` | Expect usage fields in streaming responses |
| `maxTokensField` | Override param name (e.g., `max_completion_tokens`) |
| `openRouterRouting` | OpenRouter routing metadata (JSON object) |
| `vercelGatewayRouting` | Vercel gateway routing metadata (JSON object) |

## Examples

### 1. Override OpenAI Base URL (e.g. for Groq)

```json
{
  "providers": {
    "openai": {
      "baseUrl": "https://api.groq.com/openai/v1",
      "apiKey": "gsk_...",
      "models": [
        {
          "id": "llama3-70b-8192",
          "name": "Groq Llama 3 70B",
          "contextWindow": 8192
        }
      ]
    }
  }
}
```

### 2. Azure OpenAI

Azure requires resource-specific URLs and `api-key` header instead of Bearer token.

```json
{
  "providers": {
    "azure-openai": {
      "api": "openai",
      "baseUrl": "https://my-resource.openai.azure.com/openai/deployments/my-deployment",
      "apiKey": "...",
      "authHeader": false,
      "headers": {
        "api-key": "..."
      },
      "models": [
        {
          "id": "gpt-4",
          "contextWindow": 128000
        }
      ]
    }
  }
}
```

### 3. Local LLM (Ollama)

```json
{
  "providers": {
    "ollama": {
      "api": "openai",
      "baseUrl": "http://localhost:11434/v1",
      "apiKey": "ollama",
      "models": [
        {
          "id": "llama3",
          "contextWindow": 8192
        }
      ]
    }
  }
}
```

## Secret Resolution

API keys can be plain strings, environment variables, or shell commands.

- **Environment Variable**: If the string matches an env var name (e.g. `OPENAI_API_KEY`), it is resolved.
- **Shell Command**: Prefix with `!` to execute a command.

```json
{
  "providers": {
    "openai": {
      "apiKey": "!pass show api/openai"
    }
  }
}
```

Shell commands run via `sh -c` on Unix and `cmd /C` on Windows.

### Local providers (no API key)

`ollama`, `llamacpp` (llama.cpp's `llama-server`), `mistralrs` (mistral.rs), and
`lmstudio` are recognized built-in **local** providers. `ollama`, `llamacpp`, and
`mistralrs` require **no API key** — they expose an OpenAI-compatible server on
localhost and are called without an `Authorization` header. They work
out-of-the-box without a `models.json` entry:

```bash
# Defaults: llama-server -> http://127.0.0.1:8080/v1, mistral.rs -> http://127.0.0.1:1234/v1
pi --provider llamacpp  --model ggml-org/gemma-4-E4B-it-GGUF -p "hi"
pi --provider mistralrs --model default -p "hi"
```

Provider aliases are accepted: `llama.cpp` / `llama-cpp` / `llama-server` ->
`llamacpp`, and `mistral.rs` / `mistral-rs` -> `mistralrs`.

To point at a non-default host/port, add a `models.json` entry (no `apiKey`
needed):

```json
{
  "providers": {
    "llamacpp": {
      "baseUrl": "http://127.0.0.1:9090/v1",
      "models": [ { "id": "my-model" } ]
    }
  }
}
```

## User Model Override (extending the bundled snapshot)

Pi ships with a snapshot of every provider's discovery endpoint at
`docs/provider-upstream-model-ids-snapshot.json`. The snapshot is regenerated
ahead of releases, but a new model from a provider (e.g. Anthropic shipping a
new Opus version) is invisible to `/model` until the next release.

Drop a JSON file at `<config_dir>/pi/models-override.json` to extend the
snapshot at runtime. The file uses the same shape as the bundled snapshot:

```json
{
  "anthropic": ["claude-opus-4-7"],
  "openrouter": ["anthropic/claude-opus-4-7"]
}
```

`<config_dir>` is whatever `dirs::config_dir()` reports — `~/.config` on Linux,
`~/Library/Application Support` on macOS, `%APPDATA%` on Windows. Set
`PI_MODELS_OVERRIDE=/path/to/file.json` in the environment to point pi at a
file outside the standard config directory.

Behavior:

- **Additive only.** Override entries union with the bundled snapshot. There
  is no way to *remove* a bundled model via the override file; the provider's
  next refresh will reintroduce anything you delete.
- **Survives upgrades.** The override file is in your user config directory,
  not in pi's binary, so model entries you add stay across releases until the
  bundled snapshot catches up — then they dedupe automatically.
- **Fail-safe.** A missing or malformed override file logs a debug/warning
  line and is treated as empty so a typo never breaks pi startup.
- **Provider IDs must match canonical names.** Use `anthropic`, `openai`,
  `openrouter`, etc. (the keys you see in
  `docs/provider-upstream-model-ids-snapshot.json`).

The override only affects the `/model` autocomplete catalog. To actually call
a model that pi does not yet have a built-in route for, also configure the
provider in `models.json` (sections above) — pi already routes any
`anthropic/<id>` value through the Anthropic API regardless of whether the ID
is in the snapshot.
