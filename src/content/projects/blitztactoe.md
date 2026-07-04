---
title: 'BlitzTactoe'
description: 'Real-time multiplayer tic-tac-toe with a five-second turn timer — miss your window and you forfeit the move.'
pubDate: '2026-01-18'
github: 'https://github.com/butteredsaltedtoast/blitztactoe'
stack: ['Django', 'WebSockets', 'Redis', 'JavaScript']
---

BlitzTactoe is tic-tac-toe with the calm surgically removed. Every move is on a five-second countdown — hesitate and you lose the turn. Two players connect to a room, a three-second pre-game countdown starts once both sides ready up, and the board is live from there.

## What it does

- Public matchmaking and private rooms by ID
- Server-authoritative turn timer with per-turn countdown broadcast to both clients
- Rematch voting, ready states, and automatic starter rotation between games
- Full game state survives disconnects and reconnects — walk away, come back, keep playing

## Stack

- **Django 6** with **Django Channels** on ASGI, served by **Daphne** in production
- **Redis** as both the Channels layer backend and the durable store for live game state (so a worker restart doesn't nuke in-progress matches)
- **WebSockets** end to end — no polling, no long-poll fallbacks
- Vanilla **JavaScript** and CSS on the client, static assets served via **Whitenoise**

## Architecture

The interesting piece is `game/consumers.py` — an `AsyncWebsocketConsumer` that owns the game loop. In-memory dicts (`GAMES`, `GAME_CONNECTIONS`) give fast access during a match, while every state change gets mirrored to Redis under a `game:{room_id}` key. Per-room `asyncio.Lock`s serialize moves so two clicks arriving in the same millisecond can't both land. Input validation is factored into `game/validators.py` — room IDs, move indices, turn times, and game names all get checked before touching state.
