# redoslint

**把「可能卡死你服务的那段正则」连同证据一起指出来。**

零依赖 Python CLI。扫描整个仓库，命中时给出正则里的精确片段偏移、参与歧义的
字符集，而不是只按形状猜。

```
$ redoslint pattern "^(a+)+$"
pattern: '^(a+)+$'
  RDS001 [high] (offset 1, '(a+)+'): quantifier nested inside quantifier: the
  inner quantifier's end shares the characters {'a'} with the start of the next
  outer iteration; a failing match splits the input every possible way —
  exponential time
    fix: rewrite as a single quantifier, e.g. a+ instead of (a+)+; ...
```

## 为什么需要它

现在人人都在让模型写正则。`^(\w+\s?)+$` 这类写法到处都是——只要输入来自外部、
且长度不受限，它就是一个一行代码的 DoS。

现有工具在这个工作流上都不合手：

| 工具 | 是什么 | 为什么不顶用 |
|---|---|---|
| [regexploit](https://github.com/doyensec/regexploit) | 研究型 REPL | 一次只能手工粘一条正则 |
| [recheck](https://github.com/makenowjust-labs/recheck) | Scala/JS 自动机方案 | 要 Node 工具链，赛道不同 |
| `redos` (npm) | 仅 JS | 只覆盖 JS 生态 |
| rxxr2 | 学术工具，已停更 | Java，最后一次发布 2016 |

redoslint 是零依赖的 Python CLI：能扫目录树、每条命中保留行号列号、能卡 CI。

## 三步跑通

```bash
# 1) 安装（无运行时依赖）
pip install git+https://github.com/xuange-hu/redoslint

# 2) 审一条正则，或者整个仓库
redoslint pattern "^(\w+\s?)+$"
redoslint scan ./src --fail-on medium

# 3) 接进 CI —— 达到阈值就退出码 1
redoslint scan . --sarif redoslint.sarif --fail-on high
```

仓库内自带的两个夹具，不需要联网：

```bash
redoslint scan examples/vulnerable.py   # 9 finding(s)，退出码 1
redoslint scan examples/safe.py         # no findings，退出码 0
```

## 判定依据

只按形状匹配的工具会同时报 `(a+)+` 和 `(ab+)+`——后者其实是线性的。redoslint 先把
正则解析成带字节偏移的 AST，然后对每个候选只问一个问题：**这两段能不能匹配同一批
字符？**

- `(a+)+` —— 内层 `a+` 可以在任意位置结束，下一轮外层又能从 `a` 开始 → 边界歧义
  → **RDS001, high**。
- `(ab+)+` —— `b+` 吃不到下一轮必须开头的那个 `a`，边界被钉死 → 不报。
- `(\d{1,3}\.){3}\d{1,3}`（IPv4）—— 末尾的 `.` 把组和最后一段八位组隔开 → 不报。
- `.*abc.*` —— 两个 dot，但中间夹着字面量 → 不报。

整套设计就这一句：做字符集代数，不做「正则高尔夫」。这也是为什么第二遍扫描能看到
局部视角看不到的结构：嵌在三层分组里的交替分支，仍然会在每一轮外层迭代里重新进入，
`(?:x(?:y(?:a|aa)))+` 会被报出来。

**近似性说明（不藏着）：** `\w`/`\d`/`\s` 按 ASCII 展开，`.` 一律排除 `\n`，
不考虑 `(?s)`。用到 `\p{...}` 或不在支持子集里的语法，报 **RDS099** 而不是静默跳过
——看得见的覆盖缺口，好过看不见的。

## 规则表

| ID | 级别 | 命中什么 | 典型写法 |
|---|---|---|---|
| RDS001 | high | 量词嵌套量词，边界歧义 | `(a+)+`、`((a+)a)+` |
| RDS002 | high | 量词下交替分支互相重叠 | `(a\|aa)+`、`(foo\|foobar)+` |
| RDS003 | low | 分支被更早的前缀分支遮蔽 | `user\|username` |
| RDS004 | medium | 相邻量词原子共享字符 | `\d*\d*`、`a*a*b` |
| RDS005 | medium | 有界重复叠加 | `(a{1,10}){1,10}` |
| RDS006 | high | 反向引用同一循环内捕获的组 | `(?:(\w)\1)+` |
| RDS007 | high | 量词套在可空片段上 | `(a*)+`、`(a?)*` |
| RDS008 | low | 极大的最小重复次数 | `a{5000,}` |
| RDS099 | info | 超出支持子集 | （覆盖缺口） |

级别含义按字面理解：**high** 对输入长度是指数级，**medium** 是多项式（真实存在，
但需要更长输入才疼），**low** 是卫生问题。RDS004 连续出现三个重叠量词时升级为 high。

## 支持哪些取样

Python 走 `ast`（只认真正的 `re.*` 调用点，注释和长得像的字符串不会误入）、
Go `regexp.Compile`、Java/Kotlin `Pattern.compile`、JS/TS 的 `new RegExp(...)` 与
`/.../flags` 字面量。其它语言用 `redoslint pattern "..."`，或者 `--json` 接管道。

```bash
redoslint scan . --json | jq '.reports[] | select(.worst=="high")'
redoslint scan . --sarif out.sarif --fail-on medium
```

## MCP 服务

六个工具，让 agent 不用开 shell 就能审正则：

```bash
uvx --from "redoslint[mcp]" redoslint-mcp
```

| 工具 | 用途 |
|---|---|
| `redos_scan` | 扫文件或目录 |
| `redos_pattern` | 审一条正则 |
| `redos_rules` | 列规则 |
| `redos_rule_detail` | 单条规则说明 + 修法 |
| `redos_sarif` | 输出 SARIF 2.1.0 |
| `redos_version` | 版本号 |

核心保持零依赖；`mcp` 放在 extra 里并锁在 `>=1.2,<2`（2.x 把 `FastMCP` 改名成
`MCPServer`，路径也换了）。

## 接 GitHub Actions

```yaml
- run: pip install git+https://github.com/xuange-hu/redoslint
- run: redoslint scan . --fail-on high --sarif redoslint.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: redoslint.sarif
```

退出码：`0` 干净或低于阈值，`1` 达到/超过 `--fail-on`，`2` 用法错误。

## 目录结构

```
src/redoslint/parser.py     手写正则解析器，每个节点带 span
src/redoslint/charset.py    区间集合代数（union/intersect/negate）
src/redoslint/analyze.py    full/start/end 字符集、可空性
src/redoslint/rules.py      九条规则，两遍扫描
src/redoslint/engine.py     编排、JSON、SARIF
src/redoslint/extract.py    各语言字面量提取
src/redoslint/cli.py        scan / pattern / rules / version
src/redoslint/mcp_server.py 六个 MCP 工具
examples/vulnerable.py      九条规则全部命中（CI 断言）
examples/safe.py            同样任务的安全写法（CI 断言干净）
```

## 已知边界

- 字符集按 ASCII 近似，且不建模大小写不敏感：`(?i)` 只有在模式自身分支大小写不同
  时才会消除一处真实重叠。
- 静态工具，不执行正则，因此不会给出真实耗时——确认命中后，请在带超时的子进程里
  复现一次。
- 后行断言（lookbehind）内容按「不消耗字符」处理，对歧义判定是正确的，但意味着
  「只在环视内部才危险」的模式不会被报出来。

## 参与

见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题见 [SECURITY.md](SECURITY.md)。
英文说明：[README.md](README.md)。

MIT。
