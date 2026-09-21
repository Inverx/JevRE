# JevRE

**Jev-powered decision layer for Android reverse engineering.**

```text
APK / State
    ↓
   Jev
    ↓
"What should I investigate next?"
    ↓
Unpack / Capture / Trace / Hook / Inspect
```

JevRE is an experiment in using TypeSafe AI's **Jev System One Model** as the
decision layer inside an Android reverse-engineering workflow.

JevRE does not ask Jev to reverse engineer an APK. It asks Jev to decide what
the workflow should investigate next.

Real Jev is JevRE's default and core decision engine. Mock is an explicit
offline demo and test mode; it does not use Jev.

The relationship is deliberately small and direct:

```text
ReverseState
     ↓
Jev Choice question
     ↓
Typed probability distribution
     ↓
Recommended next action
```

The APK analyzer observes safe ZIP metadata. Tools and analysts perform the
actual investigation. Jev is the fast decision layer. This MVP has no agent
loop and no generative LLM.

## What Jev is

[TypeSafe AI](https://typesafe.ai/) describes Jev as its first **System One
Model**: structured state in, typed probabilistic decisions out. It is not a
chat model and it does not generate explanations or code.

TypeSafe exposes three question primitives:

- **Choice** selects one item from predefined criteria and returns the chosen
  item, every option's probability, and confidence.
- **Score** places state on an ordered rubric and returns a distribution plus a
  probability-weighted score.
- **Noul** answers a yes/no question with the probability that the answer is
  yes.

JevRE's MVP uses **Choice** for one question:

> Given the current Android reverse-engineering state, which investigation
> step should be performed next?

The exact eight choices are:

```text
unpack
static_analysis
capture_traffic
inspect_network_stack
locate_signature
hook_java
hook_native
collect_more_evidence
```

The client follows the official TypeSafe contract documented in the
[Quick Start](https://docs.typesafe.ai/introduction/quickstart) and
[HTTP API reference](https://docs.typesafe.ai/api):

```http
POST https://api.typesafe.ai/v1/systemone
Authorization: Bearer <TYPESAFE_API_KEY>
Content-Type: application/json
```

It sends `state`, `model`, and a typed Choice under `questions`. It reads the
answer from `answers.next_action`. Jev's `confidence` and the selected option's
probability are distinct values, so JevRE displays both.

## Install

JevRE requires Python 3.10 or newer. Runtime code uses only the Python standard
library.

From the repository root, create a virtual environment:

```console
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or activate it on macOS/Linux:

```bash
source .venv/bin/activate
```

Install JevRE and check the CLI:

```console
python -m pip install -e .
jevre --help
```

For development and tests:

```console
python -m pip install -e ".[test]"
pytest
```

You can also run the checkout directly, without installing the package:

```console
python -m jevre --help
```

## Configure real Jev

Set the API key in the process environment. `TYPESAFE_API_KEY` is required for
real Jev calls. `JEV_MODEL` and `JEV_BASE_URL` are optional and default to the
values shown below. JevRE does not auto-load `.env` files and never prints the
key; `.env.example` is reference-only.

```powershell
$env:TYPESAFE_API_KEY = 'your_api_key_here'
$env:JEV_MODEL = 'jev-latest'
$env:JEV_BASE_URL = 'https://api.typesafe.ai'
```

On macOS/Linux:

```bash
export TYPESAFE_API_KEY='your_api_key_here'
export JEV_MODEL='jev-latest'
export JEV_BASE_URL='https://api.typesafe.ai'
```

Then analyze an APK or decide from an existing state:

```console
jevre analyze app.apk
jevre decide examples/packed.json
jevre doctor
```

Without `TYPESAFE_API_KEY`, real mode fails clearly. It never switches to a
heuristic after a configuration, network, HTTP, or response-schema failure.
`jevre doctor` does not call the API and exits nonzero while the required key is
missing; that result is an expected configuration diagnostic.

## Offline Mock demo

Mock is only a deterministic offline demo for tests and development.

> **Mock mode does not use Jev.**

It must be selected explicitly:

```console
jevre decide examples/packed.json --mock
jevre decide examples/signed_traffic.json --mock
jevre decide examples/hidden_traffic.json --mock
jevre analyze app.apk --mock
```

Expected top Mock actions for the bundled fixtures:

| Fixture | State signal | Expected action |
|---|---|---|
| `packed.json` | Packer suspected, one DEX | `unpack` |
| `signed_traffic.json` | Traffic visible, dynamic signature present | `locate_signature` |
| `hidden_traffic.json` | Network works but proxy traffic is unavailable | `inspect_network_stack` |

Mock output labels its values as heuristic scores and reports confidence as
`n/a`; its numbers are not Jev probabilities or calibrated confidence.

## APK analysis scope

`jevre analyze` reads the APK as a ZIP and extracts only local, static facts:

- SHA-256
- canonical root DEX count
- native `.so` count and ABIs
- asset count
- Flutter, Unity, and React Native indicators
- a small set of conservative packer fingerprints

It never extracts archive members. Dynamic facts such as visible traffic, TLS
pinning, runtime crashes, and request-signature parameters remain unknown until
you provide them in a state JSON file. `sign_present` means a dynamic request
signature; it does not mean APK signing metadata under `META-INF`.

No packer fingerprint means `Unknown`, not “unpacked.” Filename inspection
cannot prove an APK is unprotected.

## State format

```json
{
  "framework": "flutter",
  "dex_count": 2,
  "native_library_count": 14,
  "packer_suspected": null,
  "traffic_visible": false,
  "ssl_pinning_suspected": true,
  "sign_present": null,
  "runtime_crash": false,
  "notes": ["application network works normally"]
}
```

All fields are optional, but unknown field names and invalid types are rejected
so that a typo cannot silently change the decision.

## Example output

```text
JevRE

Decision Engine
------------------------------------
Engine                Jev
Requested model       jev-latest
Resolved model        jev-1.13.0

Recommended Next Action
------------------------------------
hook_native
Selected probability  0.81
Confidence            0.73
```

`Observed Signals` in the report come from the input state and APK analyzer.
They are not a generated explanation from Jev; the Choice response contains a
decision distribution, not prose reasoning.

## Test

The suite is fully offline. HTTP behavior is tested with a fake transport, so
`pytest` never consumes an API request or needs an API credential:

```console
pytest
```

Tests cover `ReverseState`, safe APK inspection, deterministic Mock decisions,
the official Jev request/response schema, and CLI behavior including the rule
that real failures never invoke Mock.

## MVP boundary and roadmap

This version is a decision layer, not an autonomous reverse-engineering agent.
It intentionally does not perform unpacking, Frida hooks, traffic capture,
protocol cracking, JADX/apktool execution, or generative LLM analysis.

Possible later work, driven by evidence from the MVP:

- feed analyst-confirmed runtime observations back into `ReverseState`;
- execute selected tools behind explicit operator controls;
- evaluate Jev calibration and decision quality over real workflows;
- escalate low-confidence Jev decisions to an expensive reasoning model;
- add richer static facts only when experiments show they improve decisions.

The experiment remains narrow: **Can Jev act as the fast System One decision
layer of an Android reverse-engineering workflow?**
