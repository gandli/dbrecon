# Changelog

All notable changes to DBRecon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-05-11

### Added

#### Core Features
- **CLI 工具** — 基于 Click 的命令行界面，支持 4 个子命令：
  - `test-connection` — 测试数据库连接，支持 SSL、自定义端口和超时
  - `fingerprint` — 应用指纹识别，自动检测 CMS 和框架
  - `scan-sensitive` — 敏感数据发现，支持按数据类型过滤
  - `full-scan` — 完整安全评估，包含指纹+敏感数据+报告生成
- **应用指纹识别引擎** — 支持 7 种应用：
  - WordPress（含 WooCommerce、Yoast SEO 插件检测）
  - Drupal 7 / Drupal 8
  - Laravel
  - Django
  - Joomla
  - Magento
  - PrestaShop
- **敏感数据扫描器** — 通过字段名匹配和数据模式匹配发现：
  - 密码（`*password*`, `*passwd*`, `*pwd*`, `*hash*`）
  - API 密钥（`*api_key*`, `*secret*`, `*token*`, `*key*`）
  - 邮箱（`*email*`, `*mail*`）
  - 手机号（`*phone*`, `*mobile*`, `*tel*`）
  - 信用卡（`*credit*`, `*card*`, `*payment*`）
  - URL（`*url*`, `*link*`, `*host*`, `*domain*`）
- **报告生成器** — 支持 5 种输出格式：
  - JSON — 结构化数据，含完整扫描元数据
  - CSV — 表格格式，便于电子表格处理
  - HTML — 带 CSS 样式的网页报告
  - Markdown — 适合文档和 GitHub
  - Console — 终端友好的格式化输出，含风险级别高亮
- **数据库管理器** — MySQL 连接管理，含连接池、SSL 支持、上下文管理器
- **Pydantic 数据模型** — `DatabaseConnection`, `TableInfo`, `FingerprintResult`, `SensitiveData`, `UrlInfo`, `ScanResult`, `ScanConfig`
- **YAML 签名配置** — `configs/signatures.yaml` 定义应用指纹和敏感数据模式

#### Testing
- **331 个测试用例**，100% 代码覆盖率（657 行源代码，0 行未覆盖）
- **测试分层架构**：
  - 单元测试（`test_*.py`）— 按模块覆盖所有公共方法和边界条件
  - 扩展测试（`test_*_extended.py`）— 覆盖错误处理、参数化场景、遗留格式
  - TDD 场景测试（`test_scenarios*.py`）— 按业务场景组织的端到端测试
- **共享 Fixtures** — `conftest.py` 提供统一的测试数据工厂
- **Pytest 配置** — 严格模式、测试标记（unit/integration/slow/cli）、警告过滤

#### TDD 场景测试（109 个用例）
- `test_scenarios.py` — 完整扫描流程、空数据库、多应用混合、连接失败恢复、CLI 端到端
- `test_scenarios_fingerprint.py` — 6 种 CMS 识别、5 种敏感数据发现、去重合并、边界条件
- `test_scenarios_models.py` — Pydantic 模型验证、5 种报告格式全功能验证

#### Development Tools
- Black 代码格式化（88 字符行宽）
- Flake8 代码检查
- Mypy 类型检查
- pytest-cov 覆盖率报告

### Changed

#### Bug Fixes
- **cli.py** — 修复 `create_dummy_scan_result` 引用未定义 `config` 变量
- **cli.py** — 修复 `create_complete_scan_result` 引用未定义 `config`/`db_manager` 变量
- **pyproject.toml** — 添加 `--strict-markers` 严格模式和测试标记定义

### Project Statistics

| 指标 | 数值 |
|------|------|
| 源代码行数 | 1,373 |
| 测试代码行数 | 5,172 |
| 测试用例数 | 331 |
| 代码覆盖率 | 100% |
| 支持的应用指纹 | 7 |
| 支持的敏感数据类型 | 6 |
| 支持的报告格式 | 5 |
| CLI 子命令 | 4 |

### Dependencies

- `click>=8.0.0` — CLI 框架
- `mysql-connector-python>=8.0.0`— MySQL 数据库连接
- `rich>=10.0.0` — 终端富文本输出
- `PyYAML>=6.0` — YAML 配置解析
- `pydantic>=1.8.0` — 数据模型和验证

#### Dev Dependencies

- `pytest>=7.0.0` — 测试框架
- `pytest-cov>=4.0.0` — 覆盖率插件
- `black>=22.0.0` — 代码格式化
- `flake8>=5.0.0` — 代码检查
- `mypy>=0.991` — 类型检查
