#!/bin/bash
# sandbox/slurm/worker_array.sbatch — SLURM array job for the M3 worker pool.
#
# One array task = one stateless worker process (humpty.king.workers.Worker)
# claiming from the shared FR-14 queue. Scale = --array size; workers are
# identical and stateless (WHITEPAPERS: "LLM agents run as thin, typed,
# stateless workers inside the orchestrator's own CEGIS loop").
#
# Usage:  sbatch --array=1-8 worker_array.sbatch KIND
#   KIND: fix | fuzz   (develop needs an LLM endpoint; run it on the
#                       orchestrator node once the gateway answers)
#
# Environment: HUMPTY_DB_URL must point at the PostgreSQL orchestrator DB
# (FR-14 queue + FR-17 events live there). Nothing else is shared.
#SBATCH --job-name=bindumpty-worker
#SBATCH --output=slurm-%A_%a.out
#SBATCH --error=slurm-%A_%a.err
#SBATCH --time=04:00:00
#SBATCH --cpus-per-task=4
#SBATCH --mem=8G
#SBATCH --array=1-8

KIND=${1:-fix}
export HUMPTY_DB_URL=${HUMPTY_DB_URL:?set HUMPTY_DB_URL to the orchestrator PostgreSQL}
export HORSE_FUZZ_BUDGET_S=${HORSE_FUZZ_BUDGET_S:-30}

cd "$SLURM_SUBMIT_DIR"
# NFR-1: the untrusted binary and candidate code run only inside the sandbox
# container; the worker process itself only orchestrates.
CONTAINER=$(command -v apptainer || command -v singularity)
if [ -n "$CONTAINER" ] && [ -f sandbox/humpty.sif ]; then
    exec $CONTAINER exec sandbox/humpty.sif \
        python -m humpty.king.worker_main --kind "$KIND" --worker-id "slurm-${SLURM_ARRAY_JOB_ID}_${SLURM_ARRAY_TASK_ID}"
else
    echo "sandbox image missing (build with: apptainer build sandbox/humpty.sif sandbox/Dockerfile)" >&2
    exit 1
fi
