# OpenVPN Web 管理平台后端服务

这是一个基于 Flask 框架开发的 OpenVPN 后端管理服务，配合前端页面可实现 VPN 用户的管理，包括查看配置、添加、删除用户等功能。

## 🌟 功能简介

- 查询当前 OpenVPN 用户配置
- 添加新的 OpenVPN 用户配置
- 删除已有用户配置
- 显示服务器状态信息

## 📁 项目结构

```bash
.
├── bin/
│   └── webui.py            # 主后端程序（Flask Web 服务）
├── config/
│   └── .env                # 配置文件，包含路径及 OpenVPN 设置
├── static/
│   ├── index.html          # 首页（用户配置管理）
│   └── login.html          # 登录页面（如有身份验证功能）
、、、bash