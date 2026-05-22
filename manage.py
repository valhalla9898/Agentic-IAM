"""Management CLI for Agentic-IAM: migrations, workers, training, rotation."""

import argparse
import os
import subprocess
import sys


def run_migrations():
    cmd = [sys.executable, "-m", "alembic", "upgrade", "head"]
    env = os.environ.copy()
    print("Running:", " ".join(cmd))
    subprocess.check_call(cmd, env=env)


def run_celery_worker():
    cmd = [
        "celery",
        "-A",
        "celery_worker.celery_app",
        "worker",
        "--loglevel=info",
        "-Q",
        "rotation",
    ]
    subprocess.check_call(cmd)


def rotate_once():
    cmd = [
        sys.executable,
        "-c",
        "from tasks.rotate_credentials import rotate_credentials; print(rotate_credentials())",
    ]
    subprocess.check_call(cmd)


def train_model(out):
    cmd = [sys.executable, "agent_intelligence_train.py", "--out", out]
    subprocess.check_call(cmd)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("migrate")
    sub.add_parser("worker")
    sub.add_parser("rotate")
    t = sub.add_parser("train")
    t.add_argument("--out", default="models/trust_score.pkl")

    args = parser.parse_args()
    if args.cmd == "migrate":
        run_migrations()
    elif args.cmd == "worker":
        run_celery_worker()
    elif args.cmd == "rotate":
        rotate_once()
    elif args.cmd == "train":
        train_model(args.out)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
