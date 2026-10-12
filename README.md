# CTF 杂项解题助手（CTF-Misc-Tool）

面向 CTF **Misc / 取证 / 隐写** 类题目的桌面解题工具：拖入题目文件 → 一键自动分析 → 直接给出 flag 候选。
自带 159 道公开题目题库（离线可练），并内置公开题目的抓取脚本，可随时扩充题库。

## 界面

卡片式一键工具台（仿参考界面的“标题 + 说明”卡片列表）：左侧 11 个分类共 45 张卡片，
顶部搜索框可过滤卡片；右上 flag 候选、右中结果详情、右下处理日志。
另提供“高级工具面板”卡片，打开经典标签页工具台做精细操作。

## 目录结构

```
CTF-Misc-Tool/
├─ CTF-Misc-Tool.exe      # 免安装主程序（双击运行）
├─ _internal/             # PyInstaller 运行时（勿删）
├─ assets/app.ico         # 图标
├─ corpus/                # 题库：index.json + 159 道题的题面与附件
├─ src/ctfmisc/           # 源码：核心引擎 + GUI
├─ tests/selftest.py      # 引擎自检（合成题目回归）
├─ tools/                 # 题库抓取、图标生成等辅助脚本
├─ build_exe.ps1          # 一键打包脚本
├─ 使用说明.txt
└─ README.md
```

## 引擎结构

| 模块 | 职责 |
| --- | --- |
| `flags.py` | flag 正则、误报过滤、候选打分与归并 |
| `filetypes.py` | 魔数识别、文本形态判断、主数据区边界（附加数据定位） |
| `codec.py` | 40+ 编码/古典密码解码器 + Beam Search 多层自动解码 |
| `carve.py` | 内嵌文件雕复（按格式结束标记精确裁剪） |
| `archive.py` | zip/gz/bz2/xz/tar/7z、伪加密修复、口令爆破、文件名编码还原 |
| `image.py` | PNG 结构/文本块/CRC、LSB（多通道/位平面）、高度修复、图片异或、zlib 流 |
| `jpegdct.py` | JPEG 熵解码 → DCT 系数域隐写提取（jsteg 规则、比特偏移、结构探测） |
| `audio.py` | WAV LSB、频谱图、DTMF、摩斯、MP3 标签 |
| `pcap.py` | pcap/pcapng 解析、TCP 流重组、HTTP 对象还原、USB 键盘还原 |
| `misc.py` | 二维码、Brainfuck/Ook!/Whitespace、JWT、哈希、RSA 弱参数攻击 |
| `pipeline.py` | 分层调度：分析 → 派生新数据 → 递归展开 → flag 归集 |
| `crypto_ext.py` | XOR 爆破与已知明文攻击、维吉尼亚/替换自动破解、AES/DES、JWT、RSA 攻击集 |
| `binary.py` | PE/ELF/Mach-O 信息卡（checksec 风格）、.pyc 反汇编、PyInstaller(PYZ) 解包 |
| `web.py` | Web 自动探测：信息收集、敏感/备份文件扫描、.git 泄露恢复、SQLi/LFI/SSTI/RCE、请求重放 |
| `docs.py` | PDF / Office 文档取证、pyjail 绕过提示、magic hash 速查 |
| `gui/cards.py` | 卡片组件与可搜索卡片列表 |
| `gui/actions.py` | 45 张卡片的具体动作实现 |
| `gui/app.py` | 主窗口（卡片台 + flag 候选 + 结果 + 日志） |
| `gui/tabs.py` | 经典标签页工具台（编码/图片/压缩包/音频/二维码/其他/题库） |

自动分析的核心思路：每个产物都可能派生出新产物（解压出的文件、解码后的文本、
提取出的位流、还原出来的 HTTP 对象……），流水线用工作队列逐层展开，配合深度/数量/时间
三重上限，并对“猜测型”变换（凯撒、栅栏、列置换等）要求更高分数才继续下钻，避免组合爆炸。

## 本地运行（开发）

```powershell
$py = "C:\Users\kun\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$env:PYTHONPATH = "outputs/CTF-Misc-Tool/src"
& $py -m ctfmisc                      # 启动界面
& $py outputs/CTF-Misc-Tool/tests/selftest.py   # 跑自检（15 项）
```

依赖：`pillow numpy cryptography opencv-python-headless pyzbar py7zr qrcode pycryptodome windnd pypdf`
（CODEX 运行时已内置 pillow/numpy/cryptography/pypdf；其余通过 pip 安装。）

## 打包 exe

```powershell
powershell -ExecutionPolicy Bypass -File outputs/CTF-Misc-Tool/build_exe.ps1
```

产物为 `work/exe-dist/CTF-Misc-Tool/`，脚本会自动把 exe 与 `_internal/` 复制回
`outputs/CTF-Misc-Tool/`，与 `corpus/`、`assets/` 组成可直接分发的目录。

## 题库更新 / 扩充

```powershell
# 1) 拉取公开归档的目录索引（只下目录，不下大文件）
git clone --depth 1 --filter=blob:none --no-checkout https://github.com/sajjadium/ctf-archives.git work/corpus/ctf-archives

# 2) 按目录索引挑选体积可控的 misc/forensic 题目并下载附件
& $py tools/build_corpus.py --repo work/corpus/ctf-archives --out outputs/CTF-Misc-Tool/corpus `
      --max-challenges 200 --max-mb 55 --per-file-mb 2.5 --ctf-limit 5
```

脚本会优先使用本地 git 对象库（零流量），否则走 jsDelivr / ghproxy 通道；
下载过的文件会缓存在 `work/corpus/blob-cache/`，重跑不会重复下载。

## 已知边界

- 只处理**本地文件型**题目；需要远程交互、OSINT 检索的题目不在范围内。
- steghide / outguess / F5 等带口令的隐写没有实现（检测到痕迹会给出提示）。
- 音频摩斯、鼠标轨迹还原属于启发式实现，结果仅供参考。
- rar 解包依赖外部 unrar，未内置。

## 验证与测试结果

1. **引擎自检**（`tests/selftest.py`，19 项合成题目）：全部通过 ——
   多层编码链、PNG LSB、PNG 尾部数据、PNG 高度修复、ZIP 注释/嵌套/伪加密/解包、
   摩斯、Brainfuck、二维码、WAV LSB、PCAP HTTP 还原、内嵌文件雕复、
   **JPEG 系数域（jsteg）往返提取**、真实 JPEG 系数解码一致性校验等。

2. **打包版自检**（`CTF-Misc-Tool.exe --selftest`，在真实打包环境里跑）：
   12 项全部通过，结果见 `自检结果.txt`（含依赖可用性与题库可读性）。

3. **真实题目批量测试**（`tools/verify_on_corpus.py`，见 `测试报告.md`）：
   从题库抽样 80 道真实公开题目自动分析，0 崩溃，平均 2 秒/题；
   36 道产出实质发现（LSB / 元数据 / 解包 / 解码等），3 道直接给出高置信 flag 候选。
   其余多数题目本身需要人工推理（重建二维码、去模糊、数学题、远程交互等），
   通用工具无法直接出 flag —— 这类题目要靠 ②③⑤ 各页手动深挖。

4. **Web 模块自测**（`tests/test_web.py`）：内置本地漏洞靶场（含 SQLite 注入点、路径穿越、
   SSTI、命令注入、真实 git 仓库），逐项验证：站点探测、敏感文件扫描（robots 提示）、
   报错型+联合查询 SQL 注入取 flag、文件包含、SSTI、命令注入、**.git 源码泄露恢复**、源码审计
   —— 11/11 通过。

5. **JPEG 系数域解码正确性**：把解出的 DCT 系数做逆变换重建图像，
   与 Pillow(libjpeg) 的解码结果逐像素比对，平均误差 0.75/255 —— 说明熵解码、
   Huffman 表、反量化、zigzag 顺序全部正确，因此“没找到数据”的结论可信。
