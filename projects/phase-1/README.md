# CS453 Phase 0 Starter

This is a starting point, not a finished project. Some of it is filled in
for you so you're not staring at a blank folder. Some of it is
deliberately left for you to write, that part is the assignment.

## What's already here

- `docker-compose.yml` — the `redis` service is mostly ready. The `api`
  service has just enough to build and expose a port. Several `# TODO`
  comments mark what you still need to add, each one points to the
  slide in the Phase 0 deck that covers it.
- `app.py` — a minimal Flask skeleton. The app instance and the
  `host="0.0.0.0"` binding are already set correctly, don't change that
  line. Routes and the Redis connection logic are marked with `# TODO`
  comments pointing to the relevant slides.
- `requirements.txt` — Python dependencies for the API container.
- `.dockerignore` / `.gitignore` — housekeeping, already set up.

## What you still need to do

- Write a `Dockerfile` for the `api` service (see Slides 6–10 in the
  Phase 0 deck).
- Fill in every `# TODO` in `docker-compose.yml` and `app.py`.
- Write your read and write endpoints in `app.py`.

## Running it

Once your Dockerfile is written and the TODOs are filled in:

```bash
docker-compose up --build
```

## Source control

You don't have to push this to git, but you should. VM resets wipe
local state, and a git remote is the only backup you'll have.

## Full requirements

This README only orients you to the files. For the complete
requirement list, deliverables, and grading checkpoints, see the
Phase 0 project handout.

