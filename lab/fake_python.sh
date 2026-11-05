#!/bin/sh
# Interpreteur factice pour presidio_python : lance fake_worker.py (meme protocole que
# pii_worker.py) a la place de Presidio. Arguments recus : pii_worker.py, options JSON.
exec python /app/fake_worker.py "${2:-}"
