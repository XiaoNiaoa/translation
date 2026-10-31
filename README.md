# Pawn Translation Toolkit

用于 SA-MP / open.mp Pawn 项目的文本提取、AI 翻译和安全回写。源码默认按 **GBK** 严格读取和写入；中间 JSON 使用 UTF-8。

## 功能

- 扫描 `.pwn` / `.inc` 文件，提取可能需要翻译的源码行。
- 通过用户配置的 OpenAI-compatible Chat Completions API 批量翻译。
- 自定义 API Base URL、API Key、Model 和请求参数，不绑定任何模型或服务商。
- 断点续翻、术语表、占位符保护和格式校验。
- 输出人工复核清单；存在复核项的源码行不会被回写。
- 回写前创建备份，并校验源码行与提取时完全一致。

## 环境

- Windows 10/11
- Python 3.9 或更新版本（仅使用 Python 标准库，无需 pip 安装第三方包）

## 快速开始

### 1. 提取 Pawn 文本

把工具放在项目目录或任意工作目录，运行：

```powershell
python extractor.py "D:\\YourServer\\gamemodes" -o translate.json
```

也可以直接扫描当前目录下的 `gamemodes`：

```powershell
python extractor.py
```

提取器只扫描 `.pwn` 和 `.inc`，严格按 GBK 解码。无法解码的文件会报告读取失败并跳过，不会用替换字符悄悄破坏文本。

### 2. 配置 API

第一次运行 `run.bat` 会从示例配置创建 `translation_config.json`，然后停止。用文本编辑器打开它，填写：

```json
{
    "api_base": "https://api.openai.com/v1",
    "api_key": "填写你自己的 API Key",
    "api_key_env": "TRANSLATION_API_KEY",
    "model": "gpt-4o-mini",
    "temperature": 0,
    "max_tokens": 4096,
    "batch_size": 8,
    "max_chars": 5000,
    "context_lines": 2,
    "timeout": 180,
    "response_format_json": true,
    "extra_body": {}
}
```

字段说明：

| 字段 | 说明 |
|---|---|
| `api_base` | OpenAI-compatible API Base URL，通常以 `/v1` 结尾；也可填写完整的 `/chat/completions` URL |
| `api_key` | 服务商发放的 API Key；留空时读取环境变量 |
| `api_key_env` | API Key 环境变量名，默认 `TRANSLATION_API_KEY` |
| `model` | 服务商要求的模型 ID |
| `temperature` | 采样温度，翻译建议 0 |
| `max_tokens` | 最大输出 token 数 |
| `batch_size` | 每批字符串数量 |
| `max_chars` | 每批输入字符估算上限 |
| `context_lines` | 给模型附带的相邻提取行数 |
| `timeout` | 单次请求超时秒数 |
| `response_format_json` | 服务商支持 JSON mode 时设为 true；不支持时设为 false |
| `extra_body` | 额外请求参数对象，供不同兼容服务使用 |

如果不想把 API Key 明文放在配置文件中，可以在 PowerShell 设置环境变量：

```powershell
$env:TRANSLATION_API_KEY = "你的 API Key"
python translate.py --config translation_config.json
```

只在当前 PowerShell 窗口生效。也可以通过 Windows 用户环境变量设置长期值。

**兼容性边界：** 本工具调用 `/chat/completions`，要求服务商返回 OpenAI-compatible 的 `choices[0].message.content`，且模型按提示返回包含 `translations` 数组的 JSON。不是所有声称兼容 OpenAI 的接口都支持 JSON mode；如果服务商不支持，将 `response_format_json` 设为 false。特殊参数可放进 `extra_body`。API Key 不要提交到公开仓库。

### 3. 开始翻译

双击 `run.bat`，或运行：

```powershell
python translate.py --config translation_config.json
```

主要输出：

- `translate.translated.json`：完整行级翻译结果。
- `translation_review.json`：需要人工复核的记录。
- `translation_cache.json`：断点续翻缓存。
- `translation_glossary.json`：首次运行自动创建的术语表。

缓存按 API Base URL 和 Model 区分。切换服务商或模型后，不会直接复用另一模型的已翻译结果；如需强制重翻，使用：

```powershell
python translate.py --config translation_config.json --no-resume
```

只用已有缓存生成预览，不请求 API：

```powershell
python translate.py --config translation_config.json --export-cache-only
```

### 4. 检查并回写

先检查 `translation_review.json` 和 `translate.translated.json`。确认无误后运行：

```powershell
python replacer.py translate.translated.json
```

回写器默认按 GBK 严格读写 Pawn 源码，修改前创建同名 `.bak` 备份。若源码自提取后发生变化，或译文不符合 GBK 编码，回写器会拒绝修改相应文件。

**不要跳过人工复核。** 对同一源码行，只要有一个字符串需要复核，该行就不会回写，避免只翻译一半。

## 目录

```text
extractor.py                     Pawn 文本提取器
translate.py                     API 翻译器
replacer.py                      GBK 安全回写器
translation_config.example.json  API 配置模板
translation_config.json          本地配置（自动创建，不提交）
run.bat                          Windows 启动入口
```

## 故障排查

- HTTP 401：检查 API Key 和服务商权限。
- HTTP 429：降低 `batch_size`，等待限流恢复后重新运行。
- JSON 解析失败：降低 `batch_size` 或提高 `max_tokens`；原始响应会保存到 `api_response_debug.txt`。
- 占位符错误：该字符串会进入复核列表，不会被安全回写。
- GBK 编码错误：检查译文是否含 GBK 无法表示的字符；不要把源码强行转换成 UTF-8 来绕过问题。

## License

请根据项目实际授权补充。
