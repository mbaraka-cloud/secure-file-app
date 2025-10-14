import multiprocessing
workers = int(multiprocessing.cpu_count() * 2 / 3) or 2
worker_class = "sync"
keepalive = 15
graceful_timeout = 30
# logs déjà envoyés en stdout/stderr via entrypoint
