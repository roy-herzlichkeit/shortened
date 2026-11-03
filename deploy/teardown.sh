#!/usr/bin/env bash
# Tears down SHORTENED. on AWS (us-east-1). Run it yourself in Git Bash with
# your own admin profile, and only after the video and the grading.
#
#   bash deploy/teardown.sh                  # delete the 3 stacks, keep the final snapshot
#   bash deploy/teardown.sh delete-snapshot  # later: delete that final snapshot
#
# Order: shortened-monitoring, shortened-backup, shortened. The main stack's
# data volume has DeletionPolicy Snapshot, so a final snapshot of /data
# (accounts, sessions, quota ledger) stays until you delete it on purpose.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
cd "$(dirname "$0")/.."
account=526660177875
state=.agent/teardown-state.txt   # .agent/ is gitignored

aws --version 2>&1 | grep -q '^aws-cli/2\.' || { echo "needs AWS CLI v2"; exit 1; }
aws sts get-caller-identity --query Account --output text | grep -qx "$account" \
  || { echo "wrong AWS account (want $account)"; exit 1; }

manual_steps() {
  cat <<EOF

=== Your manual steps (in this order) ===
1. Backup vault (ASK FIRST before deleting recovery points; each is a copy of /data):
     aws backup list-recovery-points-by-backup-vault --backup-vault-name shortened-vault \\
       --query 'RecoveryPoints[].[RecoveryPointArn,CreationDate]' --output table
     aws backup delete-recovery-point --backup-vault-name shortened-vault --recovery-point-arn <arn>   # each one
     aws backup delete-backup-vault --backup-vault-name shortened-vault
2. SSM parameters /shortened/* (the B2 settings):
     aws ssm delete-parameters --names /shortened/B2_KEY_ID /shortened/B2_APP_KEY \\
       /shortened/B2_ENDPOINT /shortened/B2_REGION /shortened/B2_BUCKET /shortened/QUOTA_MB /shortened/MAX_USERS
3. B2: remove https://shortened.herzlichkeit-zero.click from the CORS rule of
   shortened-prod (and of shortened, where it was added too). If the live site
   is gone for good, also delete the shortened-prod bucket and its app key.
4. Claude's access: run .agent/aws/cleanup-claude-access.sh (CloudShell, as you).
   Then delete the boundary. It has extra versions, so delete those first:
     aws iam list-policy-versions --policy-arn arn:aws:iam::$account:policy/shortened-boundary
     aws iam delete-policy-version --policy-arn arn:aws:iam::$account:policy/shortened-boundary --version-id <v>   # each non-default
     aws iam delete-policy --policy-arn arn:aws:iam::$account:policy/shortened-boundary
5. Your user HERZLICHKEIT=3301 (do this last; step 4 needs IAM rights):
     aws iam delete-user-policy --user-name HERZLICHKEIT=3301 --policy-name shortened-ssm-params
     aws iam detach-user-policy --user-name HERZLICHKEIT=3301 --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
6. Claude Code: claude mcp remove aws-mcp --scope local
7. Later: bash deploy/teardown.sh delete-snapshot (only once you are sure).
Not touched: the hosted zones, the ACM certificate (and its validation CNAME),
the apex/www and thakurag records, the Cutie instance and its volume.
EOF
}

case "${1:-stacks}" in
stacks)
  echo "This deletes the stacks shortened-monitoring, shortened-backup and shortened."
  echo "The site goes offline. The data volume leaves a final snapshot."
  read -r -p 'Type "teardown" to go on: ' answer
  [ "$answer" = teardown ] || { echo "stopped, nothing deleted"; exit 1; }

  vol=$(aws cloudformation describe-stacks --stack-name shortened \
        --query "Stacks[0].Outputs[?OutputKey=='DataVolumeId'].OutputValue" --output text 2>/dev/null || true)
  start=$(date -u +%FT%TZ)
  [ -n "$vol" ] && [ "$vol" != None ] && echo "$vol $start" >"$state"

  for s in shortened-monitoring shortened-backup shortened; do
    if ! aws cloudformation describe-stacks --stack-name "$s" >/dev/null 2>&1; then
      echo "skip   $s (not found)"; continue
    fi
    aws cloudformation update-termination-protection --stack-name "$s" --no-enable-termination-protection >/dev/null
    echo "delete $s ..."
    aws cloudformation delete-stack --stack-name "$s"
    if ! aws cloudformation wait stack-delete-complete --stack-name "$s"; then
      echo "FAILED to delete $s. Stopping here. See why with:"
      echo "  aws cloudformation describe-stack-events --stack-name $s --max-items 15"
      exit 1
    fi
    echo "done   $s"
  done

  if [ -f "$state" ]; then
    read -r vol start <"$state"
    echo
    echo "Final snapshot of $vol (kept; delete it later with: bash deploy/teardown.sh delete-snapshot):"
    aws ec2 describe-snapshots --owner-ids self --filters "Name=volume-id,Values=$vol" \
      --query "Snapshots[?StartTime>='$start'].[SnapshotId,StartTime,State,VolumeSize]" --output table
  fi
  manual_steps
  ;;

delete-snapshot)
  [ -f "$state" ] || { echo "no $state: run the stack teardown first"; exit 1; }
  read -r vol start <"$state"
  ids=$(aws ec2 describe-snapshots --owner-ids self --filters "Name=volume-id,Values=$vol" \
        --query "Snapshots[?StartTime>='$start'].SnapshotId" --output text)
  [ -n "$ids" ] && [ "$ids" != None ] || { echo "no final snapshot of $vol found"; exit 0; }
  echo "Final snapshot(s) of $vol: $ids"
  echo "This is the last copy of the accounts database outside the backup vault."
  read -r -p 'Type "delete snapshot" to delete it: ' answer
  [ "$answer" = "delete snapshot" ] || { echo "stopped, nothing deleted"; exit 1; }
  for id in $ids; do
    aws ec2 delete-snapshot --snapshot-id "$id"
    echo "deleted $id"
  done
  rm -f "$state"
  ;;

*)
  echo "usage: bash deploy/teardown.sh [stacks|delete-snapshot]"; exit 2 ;;
esac
