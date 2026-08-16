#!/bin/bash

cd /run/secrets
for file in `ls`
do
  export ${file}=`cat ${file}`
done
# Explicit, not `cd -`. The working directory is the whole point of the block
# below, so it should not depend on OLDPWD happening to be right.
cd /iriswebapp

# CELERY BEAT NEEDS A WRITABLE SCHEDULE FILE.
#
# The vendor entrypoint runs, verbatim:
#     celery -A app.celery worker -E -B -l INFO
# `-B` embeds Beat, and Beat opens its shelve DB at `celerybeat-schedule`
# RELATIVE TO THE CWD. That CWD must be /iriswebapp — `app` is not on
# PYTHONPATH and is importable from nowhere else — and /iriswebapp is
# root:root 755 while this container deliberately runs as uid 65534. So Beat
# could not create its file and died on every boot:
#
#   [ERROR/Beat] Removing corrupted schedule file 'celerybeat-schedule':
#                error(13, 'Permission denied')
#   _gdbm.error: [Errno 13] Permission denied: 'celerybeat-schedule'
#   [ERROR/Beat] Process Beat
#
# and then, one second later, `celery@… ready.` — the WORKER survives, Beat
# does not. Nothing looks wrong: the container stays Up, the install log says
# IRIS deployed successfully, and every IRIS periodic task
# (task_check_available_updates, task_update_worker, the scheduled module
# hooks) is silently dead. Observed on the 2026-08-16 install.
#
# Fixed by naming the schedule file instead of moving the CWD. `cd /tmp` was
# the obvious fix and is WRONG — it breaks `import app` and takes the worker
# down with it, which is strictly worse than losing Beat.
#
# The file is deliberately ephemeral (/tmp, not a volume): it stores only
# last-run timestamps, which Beat rebuilds from the app's schedule. Losing it
# across a restart costs at most one duplicate task run.
#
# Do NOT "simplify" this back to calling iris-entrypoint.sh — it hardcodes the
# celery line with no way to pass -s. The line below is that same command plus
# -s, so if a future IRIS release changes its worker invocation, re-check it
# here. Dropping the `& while true; sleep 2` supervisor is intentional: exec'ing
# celery makes it PID 1, so signals and `docker stop` work properly.
beat_schedule="${IRIS_BEAT_SCHEDULE:-/tmp/celerybeat-schedule}"
mkdir -p "$(dirname "$beat_schedule")" 2>/dev/null || true

exec /iriswebapp/wait-for-iriswebapp.sh iris-app:8000 \
     celery -A app.celery worker -E -B -l INFO -s "$beat_schedule"
