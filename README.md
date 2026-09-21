# JevRE

**Jev-powered decision layer for Android reverse engineering.**

**Jev 驱动的 Android 逆向决策层。**

[English](#english) · [简体中文](#zh-cn)

---

<a id="english"></a>

# English

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
values shown below.

JevRE does not auto-load `.env` files and never prints the key;
`.env.example` is reference-only.

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

It never extracts archive members.

Dynamic facts such as visible traffic, TLS pinning, runtime crashes, and
request-signature parameters remain unknown until you provide them in a state
JSON file.

`sign_present` means a dynamic request signature; it does not mean APK signing
metadata under `META-INF`.

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

Tests cover:

- `ReverseState`
- safe APK inspection
- deterministic Mock decisions
- the official Jev request/response schema
- CLI behavior
- the rule that real failures never invoke Mock

## MVP boundary and roadmap

This version is a decision layer, not an autonomous reverse-engineering agent.

It intentionally does not perform:

- unpacking
- Frida hooks
- traffic capture
- protocol cracking
- JADX/apktool execution
- generative LLM analysis

Possible later work, driven by evidence from the MVP:

- feed analyst-confirmed runtime observations back into `ReverseState`;
- execute selected tools behind explicit operator controls;
- evaluate Jev calibration and decision quality over real workflows;
- escalate low-confidence Jev decisions to an expensive reasoning model;
- add richer static facts only when experiments show they improve decisions.

The experiment remains narrow:

> **Can Jev act as the fast System One decision layer of an Android
> reverse-engineering workflow?**

---

<a id="zh-cn"></a>

# 简体中文

```text
APK / 当前状态
      ↓
     Jev
      ↓
“下一步最值得调查什么？”
      ↓
脱壳 / 抓包 / 跟踪 / Hook / 检查
```

JevRE 是一个实验性项目，尝试将 TypeSafe AI 的 **Jev System One Model**
作为 Android 逆向工程工作流中的快速决策层。

JevRE 并不是让 Jev 直接“逆向一个 APK”。

它真正向 Jev 提出的问题是：

> **根据当前已经掌握的 Android 逆向状态，下一步最值得执行哪一种调查动作？**

真实 Jev 是 JevRE 默认且核心的决策引擎。

Mock 则是一个需要显式启用的离线演示与测试模式，**不会调用 Jev**。

整个关系被刻意保持得非常简单：

```text
ReverseState
     ↓
Jev Choice 问题
     ↓
带类型的概率分布
     ↓
推荐下一步调查动作
```

APK Analyzer 只负责观察安全的 ZIP 静态元数据。

真正的逆向分析仍然由分析人员和外部工具完成，而 Jev 负责作为一个快速的
System One 决策层。

当前 MVP：

- 没有 Agent Loop
- 没有自动执行逆向工具
- 没有生成式 LLM
- 不会直接对 APK 进行完整逆向

## Jev 是什么

[TypeSafe AI](https://typesafe.ai/) 将 Jev 描述为其首个
**System One Model**。

它的基本形式可以理解为：

```text
结构化状态输入
      ↓
带类型的概率决策输出
```

Jev 不是聊天模型，也不会生成代码、分析文章或者自然语言推理过程。

TypeSafe 当前提供三种问题原语：

- **Choice**
  从预定义选项中选择一个结果，同时返回所有选项的概率以及 confidence。

- **Score**
  根据有序评分标准对当前状态进行评分，并返回概率分布以及概率加权得分。

- **Noul**
  回答一个 Yes / No 问题，并返回答案为 Yes 的概率。

JevRE 当前 MVP 只使用 **Choice**。

核心问题是：

> 根据当前 Android 逆向工程状态，下一步应该执行哪一种调查动作？

目前固定提供八种选择：

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

对应大致含义：

```text
unpack                  脱壳 / 解包
static_analysis         静态分析
capture_traffic         抓取网络流量
inspect_network_stack   检查网络栈
locate_signature        定位动态签名逻辑
hook_java               Hook Java 层
hook_native             Hook Native 层
collect_more_evidence   继续收集更多证据
```

客户端遵循 TypeSafe 官方文档中的
[Quick Start](https://docs.typesafe.ai/introduction/quickstart)
以及
[HTTP API reference](https://docs.typesafe.ai/api)。

请求格式：

```http
POST https://api.typesafe.ai/v1/systemone
Authorization: Bearer <TYPESAFE_API_KEY>
Content-Type: application/json
```

JevRE 会发送：

- `state`
- `model`
- `questions` 中带类型的 Choice

随后从：

```text
answers.next_action
```

读取决策结果。

需要注意：

**Jev 的 `confidence` 与被选中选项自身的 probability 是两个不同的值。**

因此 JevRE 会同时显示它们。

## 安装

JevRE 需要：

```text
Python >= 3.10
```

运行时仅使用 Python 标准库。

首先在项目根目录创建虚拟环境：

```console
python -m venv .venv
```

Windows PowerShell：

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS / Linux：

```bash
source .venv/bin/activate
```

安装 JevRE：

```console
python -m pip install -e .
```

检查 CLI：

```console
jevre --help
```

如果需要运行开发测试：

```console
python -m pip install -e ".[test]"
pytest
```

也可以不安装 package，直接从源码目录运行：

```console
python -m jevre --help
```

## 配置真实 Jev

真实 Jev 请求需要：

```text
TYPESAFE_API_KEY
```

可选环境变量：

```text
JEV_MODEL
JEV_BASE_URL
```

默认值如下。

Windows PowerShell：

```powershell
$env:TYPESAFE_API_KEY = 'your_api_key_here'
$env:JEV_MODEL = 'jev-latest'
$env:JEV_BASE_URL = 'https://api.typesafe.ai'
```

macOS / Linux：

```bash
export TYPESAFE_API_KEY='your_api_key_here'
export JEV_MODEL='jev-latest'
export JEV_BASE_URL='https://api.typesafe.ai'
```

JevRE：

- 不会自动加载 `.env`
- 不会打印 API Key
- `.env.example` 仅作为配置参考

配置完成后，可以直接分析 APK：

```console
jevre analyze app.apk
```

或者根据已有 ReverseState 做决策：

```console
jevre decide examples/packed.json
```

检查配置：

```console
jevre doctor
```

如果没有配置 `TYPESAFE_API_KEY`，真实 Jev 模式会明确失败。

发生以下错误时：

```text
配置错误
网络错误
HTTP 错误
返回数据 Schema 错误
```

JevRE **不会自动切换到 Mock 或启发式规则**。

这是有意设计的行为。

`jevre doctor` 不会调用真实 API。

如果必要的 API Key 缺失，它会以非零状态退出，这属于正常的配置诊断结果。

## 离线 Mock 模式

Mock 是一个确定性的离线演示与测试模式。

> **Mock 模式不会调用 Jev。**

必须显式添加：

```text
--mock
```

例如：

```console
jevre decide examples/packed.json --mock
jevre decide examples/signed_traffic.json --mock
jevre decide examples/hidden_traffic.json --mock
jevre analyze app.apk --mock
```

项目自带测试状态的预期结果：

| Fixture | 状态特征 | 预期动作 |
|---|---|---|
| `packed.json` | 疑似加固，仅发现一个 DEX | `unpack` |
| `signed_traffic.json` | 网络流量可见，同时存在动态签名 | `locate_signature` |
| `hidden_traffic.json` | App 网络正常，但代理无法获得流量 | `inspect_network_stack` |

Mock 输出中的数值会明确标记为：

```text
heuristic scores
```

并且 confidence 会显示：

```text
n/a
```

这些数值：

- 不是 Jev probability
- 不是校准后的 confidence
- 不能与真实 Jev 输出混为一谈

## APK 分析范围

`jevre analyze` 会把 APK 当作 ZIP 文件读取。

当前只提取安全的本地静态信息：

- SHA-256
- 根目录标准 DEX 数量
- Native `.so` 数量
- ABI 架构
- assets 数量
- Flutter 特征
- Unity 特征
- React Native 特征
- 少量保守的加固指纹

JevRE **不会解压 APK 中的文件到磁盘**。

动态信息不会通过静态 APK 分析自动推断，例如：

```text
网络流量是否可见
是否存在 TLS Pinning
运行时是否崩溃
是否存在动态请求签名
```

这些信息必须由分析人员通过 state JSON 提供。

例如：

```text
sign_present
```

表示的是：

> 动态网络请求中是否存在签名参数

它**不是**指：

```text
META-INF
```

中的 APK 签名元数据。

同时：

> 没有发现已知加固指纹 ≠ APK 一定没有加固

如果无法确定：

```text
packer_suspected = Unknown
```

文件名和 ZIP 结构本身无法证明 APK 一定处于未保护状态。

## State 格式

示例：

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

所有字段均为可选。

但是：

- 未知字段名
- 非法数据类型

都会被拒绝。

这样可以避免因为字段拼写错误而悄悄改变 Jev 的决策输入。

## 输出示例

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

报告中的：

```text
Observed Signals
```

来自：

- 用户输入的 ReverseState
- APK Analyzer

它们**不是 Jev 生成的自然语言解释**。

Choice 返回的是一个决策概率分布，而不是一段推理文本。

## 测试

测试套件完全离线。

HTTP 行为通过 Fake Transport 模拟，因此执行：

```console
pytest
```

不会：

- 消耗真实 API 请求
- 使用真实 API Key
- 连接 TypeSafe 服务

当前测试覆盖：

- `ReverseState`
- APK 安全静态检查
- Mock 确定性决策
- 官方 Jev Request / Response Schema
- CLI 行为
- 真实 Jev 调用失败时绝不自动进入 Mock 的规则

## MVP 边界与 Roadmap

当前版本只是：

> **Android 逆向工作流中的决策层**

而不是：

> **自主 Android 逆向 Agent**

JevRE 当前不会自动执行：

- APK 脱壳
- Frida Hook
- 网络抓包
- 协议破解
- JADX
- apktool
- 自动 Native 分析
- 生成式 LLM 分析

后续可能探索：

- 将分析人员确认后的运行时信息重新写入 `ReverseState`
- 在明确的人类控制下调用实际逆向工具
- 在真实逆向工作流中测试 Jev 的决策质量与校准情况
- 当 Jev confidence 较低时升级到成本更高的 reasoning model
- 只有在实验能够证明有效时，才继续增加更多静态 APK 特征

JevRE 当前实验始终围绕一个非常明确的问题：

> **Jev 能否作为 Android 逆向工程工作流中快速的 System One 决策层？**

---

## Project status / 项目状态

JevRE is currently an experimental MVP.

JevRE 当前属于实验性 MVP，用于探索 Jev 在 Android 逆向工作流决策中的实际价值。

Contributions, experiments, issues, and feedback are welcome.

欢迎通过 Issues 提交实验结果、问题反馈与改进建议。
