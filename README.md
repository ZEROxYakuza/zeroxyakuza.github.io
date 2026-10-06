# ZEROxYakuza Security Research Blog

Personal vulnerability research blog built with Jekyll.

## 1. Create the repository

Create a GitHub repository named:

`YOUR_USERNAME.github.io`

Then replace `YOUR_USERNAME` in `_config.yml`.

## 2. Push

```bash
git init
git branch -M main
git add .
git commit -m "Initial security research blog"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_USERNAME.github.io.git
git push -u origin main
```

## 3. Enable GitHub Pages

In GitHub:

`Settings → Pages → Build and deployment → Source → GitHub Actions`

The included workflow will build and deploy the site.

## 4. Local development

Install Ruby, Bundler and Jekyll.

```bash
bundle install
bundle exec jekyll serve
```

Open:

`http://127.0.0.1:4000`

## Writing a post

Create:

`_posts/YYYY-MM-DD-title.md`

Example front matter:

```yaml
---
title: "My research"
date: 2026-09-21 10:00:00 +0200
categories: [Windows, Kernel]
tags: [windows, kernel, reversing]
description: "Short description."
---
```

## Structure

- `_posts/` — blog posts
- `_research/` — long-form research
- `_tabs/` — About, Research, Archives and Tags
- `assets/css/` — styling
- `assets/js/` — theme/mobile behaviour
- `.github/workflows/pages.yml` — deployment


## Categories

The blog uses only these seven primary categories:

- Windows
- Linux
- Kernel
- Userland
- Reverse Engineering
- Exploitation
- Vulnerability Research

Use `tags` for narrower technical subjects such as `WinDbg`, `IDA`, `UAF`,
`heap`, `IOCTL`, `x64dbg`, `Ghidra`, `SLAB`, etc.
