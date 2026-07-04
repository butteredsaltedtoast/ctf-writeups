---
title: 'Bunkai'
description: 'Chrome extension that turns any highlighted Japanese text into an AI-powered, word-by-word breakdown in-context.'
pubDate: '2026-07-04'
github: 'https://github.com/butteredsaltedtoast/bunkai'
stack: ['JavaScript', 'Chrome API', 'Gemini']
---

Bunkai (分解, "breakdown") is a Chrome extension for people learning Japanese. Highlight any Japanese text on any webpage and a popup appears with the sentence translated naturally into English, followed by a per-word analysis: reading in hiragana, part of speech, dictionary meaning, and — the point of the whole thing — what the word is actually doing in *that specific sentence*.

Dictionary lookups tell you what a word means. Bunkai tells you what it means *here*.

## How it works

Four files carry the whole extension:

- **`manifest.json`** — Manifest V3 declaration, permissions (`activeTab`, `scripting`, `contextMenus`, `storage`), content script matches on `<all_urls>`
- **`content.js`** — injected on every page, listens for text selection, positions and renders the breakdown popup
- **`background.js`** — service worker that receives the selected text, calls Gemini, and returns structured JSON back to the content script
- **`popup.css`** — Catppuccin Mocha color palette, dismisses on outside click

A separate `settings.html` + `settings.js` handles the extension popup for storing your Gemini API key in `chrome.storage`, with two toggles: enable/disable the extension globally, and require Shift+highlight to trigger analysis (on by default, so casual selecting doesn't burn quota).

## Design

The icon is the kanji 分 in a pink-to-purple gradient on a transparent background, designed in Inkscape and exported at 16 / 48 / 128 px for the manifest.

## Stack

- **JavaScript** (no framework, no bundler — the whole extension ships as raw files)
- **Chrome Extensions API** on Manifest V3
- **Google Gemini API** with `gemini-2.5-flash-lite` for the breakdown, prompted for a strict JSON schema so the popup can render each field without any parsing acrobatics
