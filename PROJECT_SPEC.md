# VINA - Vulnerability Intelligence & Network Analyzer

You are my senior software architect and Python engineer.

## Objective

Build a production-quality Python framework named VINA.

The goal is NOT to automatically exploit systems.

The goal is to automate reconnaissance, scanning, aggregation, deduplication, AI-assisted prioritization, reporting, and manual verification planning.

The framework will orchestrate existing security tools already installed on my Linux system.

## Target Platform

Operating System:
- Pop!_OS (Ubuntu-based Linux)

Python:
- Python 3.12+

Architecture:
- Modular
- Async
- Production-quality
- Easily extensible

Never generate quick prototypes.
Never generate spaghetti code.
Never generate huge files.

Always create modular code.

--------------------------------------------------

Installed Tools

Recon

- subfinder
- assetfinder
- amass

Host Discovery

- httpx

Port Scanning

- naabu
- nmap

Technology Detection

- WhatWeb

Crawling

- katana

Historical URLs

- gau
- waybackurls

Filtering

- gf
- qsreplace
- uro

Scanning

- nuclei
- dalfox
- ffuf

Proxy

- Burp Suite

Languages

- Python
- Go

--------------------------------------------------

Project Structure

vina/

main.py
cli.py

config/

core/

modules/

models/

parsers/

reports/

templates/

output/

logs/

tests/

docs/

--------------------------------------------------

Coding Rules

Always

- Use Typer for CLI
- Use Rich for terminal output
- Use asyncio wherever possible
- Use subprocess safely
- Never use shell=True
- Add logging
- Add exception handling
- Add type hints
- Add docstrings
- Use dataclasses or Pydantic models
- Return structured Python objects
- Save JSON outputs

Never

- Remove existing functionality
- Rewrite unrelated modules
- Break APIs
- Duplicate code

--------------------------------------------------

Pipeline

Target

↓

Recon

↓

Alive Hosts

↓

Port Scan

↓

Technology Detection

↓

Crawler

↓

Historical URLs

↓

Parameter Discovery

↓

Vulnerability Scan

↓

Aggregate

↓

Deduplicate

↓

AI Analysis

↓

Markdown Report

↓

HTML Report

--------------------------------------------------

Every module must

Input

↓

Receive structured objects

↓

Run tools

↓

Parse output

↓

Return structured Python models

↓

Save JSON

No module should directly print findings.

--------------------------------------------------

AI Responsibilities

The AI never claims a vulnerability exists.

Instead it

- ranks findings
- explains findings
- suggests manual verification
- generates Burp requests
- generates payload ideas
- identifies attack chains
- produces Markdown

--------------------------------------------------

Quality

Every module must be independently testable.

Every tool invocation must have timeout handling.

Everything should work from a single command.

vina scan target.com

End Goal

Build a framework comparable in quality to ReconFTW or BBOT, but focused on AI-assisted analysis rather than automated exploitation.