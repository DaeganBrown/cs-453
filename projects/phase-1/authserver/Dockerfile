FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py make_clients.py ./
ENV PORT=9000
EXPOSE 9000
# --preload so keys are created once, before the workers fork.
CMD ["sh", "-c", "gunicorn --preload -w 2 -b 0.0.0.0:${PORT} app:app"]
