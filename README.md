# github - Entra ID sync

# run it by docker

```bash
docker run -it --rm -v $(pwd)/.env:/app/.env -v $(pwd)/.env:/app/.env -w /app ghcr.io/cloudfieldcz/entraid-github python sync.py
```
