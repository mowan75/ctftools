# CTF 杂项解题助手（CTF-Misc-Tool）

面向 CTF **Misc / 取证 / 隐写** 类题目的桌面解题工具：拖入题目文件 → 一键自动分析 → 给出 flag 候选。
内置 159 道公开题目题库（离线可练）；分析题库里的题目时，会自动带出题面、flag 格式并据此给候选加权。

## 界面

- **顶部渐变栏**：搜索框 +「打开文件」+「全自动分析」，任何页面都能直接开始
- **左侧双列卡片台**：按「经典题型速查 / 一键分析 / Misc / Web / Crypto / Reverse」分组，
  共 106 项功能；搜索框可按功能名、关键词过滤
- **右侧**：flag 候选（双击复制）、「结果 / 日志 / 题面」三个页签
- **状态栏**：实时进度、当前文件、生成目录
- 「高级工具面板」保留经典标签页工具台，用来做精细操作

## 目录结构

```
CTF-Misc-Tool/
├─ CTF-Misc-Tool.exe      # 免安装主程序（双击运行）
├─ _internal/             # PyInstaller 运行时（勿删）
├─ assets/app.ico         # 图标
├─ corpus/                # 题库：index.json + 159 道题的题面与附件
├─ src/ctfmisc/           # 源码：核心引擎 + GUI
├─ tests/selftest.py      # 引擎自检（合成题目回归）
├─ build_exe.ps1          # 一键打包脚本
├─ 使用说明.txt
└─ README.md
```

## 引擎结构

| 模块 | 职责 |
| --- | --- |
| `flags.py` | flag 正则、误报过滤（随机串/未知前缀）、候选打分与归并 |
| `filetypes.py` | 魔数识别、文本形态判断、主数据区边界（附加数据定位） |
| `codec.py` | 40+ 编码/古典密码解码器 + Beam Search 多层自动解码 |
| `carve.py` | 内嵌文件雕复（按格式结束标记精确裁剪） |
| `archive.py` | zip/gz/bz2/xz/tar/7z、伪加密修复、口令爆破（CRC 校验）、文件名编码还原 |
| `image.py` | PNG 结构/文本块/CRC、LSB（numpy 向量化）、位平面、高度修复、图片异或、zlib 流、低对比度色差增强 |
| `jpegdct.py` | JPEG 熵解码 → DCT 系数域隐写提取（jsteg 规则、比特偏移、结构探测） |
| `audio.py` | WAV LSB、频谱图、DTMF、摩斯、MP3 标签 |
| `pcap.py` | pcap/pcapng 解析、TCP 流重组、HTTP 对象还原、USB 键盘还原 |
| `misc.py` | 二维码、Brainfuck/Ook!/Whitespace、JWT、哈希、RSA 弱参数攻击 |
| `ocr.py` | 图片文字识别（RapidOCR）：大图自动降采样、OCR 误读归一化 |
| `pipeline.py` | 分层调度：容器优先 → 结构/尾部 → 递归展开 → flag 归集；单题时间片 |
| `corpusinfo.py` | 题库题面识别：自动匹配 corpus 题目、取 flag 格式与题面提示 |
| `crypto_ext.py` | XOR 爆破与已知明文攻击、维吉尼亚/替换自动破解、AES/DES、JWT、RSA 攻击集 |
| `binary.py` | PE/ELF/Mach-O 信息卡（checksec 风格）、.pyc 反汇编、PyInstaller(PYZ) 解包 |
| `web.py` | Web 自动探测：信息收集、敏感/备份文件扫描、.git 泄露恢复、SQLi/LFI/SSTI/RCE、请求重放 |
| `docs.py` | PDF / Office 文档取证、pyjail 绕过提示、magic hash 速查 |
| `gui/theme.py` | 配色、字体、圆角控件与 ttk 主题 |
| `gui/cards.py` | 双列卡片网格、折叠分组、搜索过滤 |
| `gui/app.py` | 主窗口（渐变栏 + 卡片台 + flag/结果/日志/题面） |
| `gui/tabs.py` | 经典标签页工具台（编码/图片/压缩包/音频/二维码/其他/题库） |
| `gui/actions.py` | 106 张卡片的具体动作实现 |

自动分析的核心思路：

1. **先便宜后昂贵**：先看文件尾附加数据、内嵌容器（zip/png…），容器优先入队，
   再去跑整张图的 LSB/jsteg/OCR，避免大图把时间预算吃光。
2. **每个产物都可能派生新产物**（解压出的文件、解码后的文本、LSB 位流、还原的 HTTP 对象……），
   流水线用工作队列逐层展开，配合深度/数量/时间三重上限。
3. **猜测型变换不递归**：凯撒/ROT/栅栏等对任何文本都能“变出东西”，只有命中 flag 才展示，
   避免指数级刷屏；编码型变换（Base/Hex/URL…）才继续下钻。
4. **口令来自上下文**：文件名、文件头尾的可打印串、README 题面都会作为 zip 口令候选，
   配合 CRC 校验避免“假口令”。
5. **题库感知**：命中 corpus 题目时，题面里的 `flag 格式` 会直接参与打分；结果页可切到「题面」查看原题。

## 本地运行（开发）

```powershell
$env:PYTHONPATH = "src"
python -m ctfmisc                 # 启动界面
python tests/selftest.py          # 跑引擎自检（49 项）
```

依赖：`pillow numpy cryptography opencv-python-headless pyzbar py7zr qrcode pycryptodome windnd pypdf`
（可选：`rapidocr_onnxruntime` 用于图片文字识别）。

## 打包 exe

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1
```

脚本在仓库根目录直接执行：产物先落到 `build/`，再自动把 `CTF-Misc-Tool.exe` 与 `_internal/`
复制回根目录，并裁掉用不到的 OpenCV ffmpeg 后端。

## 题库

`corpus/index.json` 记录每道题的赛事/年份/分类/题面/附件/flag 格式，附件在同名目录下。
题库抽自公开归档（[sajjadium/ctf-archives](https://github.com/sajjadium/ctf-archives)）。
要扩充题库，按同样的目录结构添加题目并更新 `index.json` 即可；程序对题库只读，不会修改原文。

## 已知边界

- 只处理**本地文件型**题目；需要远程交互、OSINT 检索的题目不在范围内。
- steghide / outguess / jphide / F5 等带口令的隐写未实现（检测到痕迹会给出提示）。
- 纯视觉推理题（去模糊、重建被破坏的二维码、拼图）仍需人工判断。
- rar 解包依赖外部 unrar，未内置。

## 验证与测试结果

1. **引擎自检**（`tests/selftest.py`，49 项合成题目）：全部通过 —— 多层编码链、PNG LSB、
   PNG 尾部数据、PNG 高度修复、ZIP 注释/嵌套/伪加密/解包、摩斯、Brainfuck、二维码、
   WAV LSB、PCAP HTTP 还原、内嵌文件雕复、JPEG 系数域往返提取、Base 家族、复合模数 ECC 等。

2. **打包版自检**（`CTF-Misc-Tool.exe --selftest`）：0 失败（运行 `CTF-Misc-Tool.exe --selftest` 可复现，含依赖可用性与题库可读性）。

3. **题库抽样回归**（12 道公开题）：优化后平均 **14.4 秒/题**（优化前 38.6 秒）；其中
   `1337UP/In_Plain_Sight` 可完整自动解出——从 JPEG 尾部取出口令、解开加密 zip、对近白色图片
   做色差增强后 OCR，得到 flag。其余多数题为纯视觉/人工推理，通用工具无法直接出 flag。

4. **Web 模块自测**（`tests/test_web.py`）：内置本地漏洞靶场（SQLite 注入、路径穿越、SSTI、
   命令注入、真实 git 仓库），11/11 通过。

5. **JPEG 系数域解码正确性**：把解出的 DCT 系数逆变换重建图像，与 Pillow(libjpeg) 逐像素比对，
   平均误差 0.75/255 —— 说明熵解码、Huffman 表、反量化、zigzag 顺序正确。