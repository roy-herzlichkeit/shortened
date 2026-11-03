# Deploying SHORTENED. to AWS

`shortened.yaml` is one CloudFormation stack in **us-east-1**. It runs the app
on one EC2 t4g.small behind CloudFront, at
`https://shortened.herzlichkeit-zero.click`. Every resource that takes tags is
tagged `Project=shortened`.

```
viewer ──HTTPS──▶ CloudFront ──HTTPS (443, CloudFront prefix list only)──▶ EIP ─▶ EC2 t4g.small
  (ACM cert)                     (Let's Encrypt cert on the origin)                 └ docker: shortened
                                                                                    └ /data = separate EBS volume (SQLite)
```

## What the stack creates

| Resource | Notes |
| --- | --- |
| `OriginSecurityGroup` (`shortened-origin`) | Inbound 443 from `pl-3b927c52` (CloudFront origin-facing) only. No SSH; use SSM Session Manager. |
| `ElasticIP` and `ElasticIPAssociation` | CloudFront reaches the origin by the EIP's `ec2-a-b-c-d.compute-1.amazonaws.com` name. |
| `InstanceRole` (`shortened-instance-role`) and `InstanceProfile` (`shortened-instance-profile`) | Permissions boundary `shortened-boundary`, `AmazonSSMManagedInstanceCore`, read `/shortened/*` in SSM, and Route 53 TXT changes only for `_acme-challenge.shortened.herzlichkeit-zero.click`. |
| `DataVolume` and `DataVolumeAttachment` | 8 GiB gp3, encrypted, mounted at `/data`. `DeletionPolicy` and `UpdateReplacePolicy` are `Snapshot`. |
| `Server` | t4g.small, standard CPU credits, latest AL2023 arm64 AMI (SSM parameter), IMDSv2 with hop limit 2, 8 GiB encrypted gp3 root, no key pair. |
| `Distribution` | Existing ACM certificate, CachingDisabled and AllViewer managed policies, all 7 methods, redirect to HTTPS, PriceClass_200, HTTP/2 and 3, IPv6. |
| `SiteRecordA` and `SiteRecordAAAA` | Aliases to the distribution in the `herzlichkeit-zero.click` zone. |

The stack does **not** create the hosted zone, the ACM certificate, the SSM
parameters or the permissions boundary. They already exist or you create them
separately, and a stack delete leaves them alone.

### What the instance does on first boot (UserData)

The log is at `/var/log/shortened-bootstrap.log`.

1. Waits for the data volume by its `/dev/disk/by-id` name, formats it as XFS
   only if it is blank, adds it to fstab by UUID and mounts it on `/data`
   (owner 10001, the container user).
2. Installs docker, git and python3.
3. Writes `shortened-env`. At every service start it turns SSM
   `/shortened/*` into `/etc/shortened.env` (mode 0600). It never prints
   values.
4. Installs `shortened.service`. This runs the container with port 443 mapped
   to 8443, TLS from `/etc/shortened/tls`, `COOKIE_SECURE=true` and
   `TRUST_PROXY=true`.
5. Clones `AppRef` from GitHub and runs `docker build` on the instance (arm64).
6. Installs certbot and certbot-dns-route53 in a venv. Requests the
   Let's Encrypt certificate with DNS-01, and a deploy hook copies it to
   `/etc/shortened/tls` and restarts the app. A systemd timer runs
   `certbot renew` twice a day.

## Parameters

| Name | Default | Notes |
| --- | --- | --- |
| `SiteName` | `shortened.herzlichkeit-zero.click` | |
| `HostedZoneId` | `Z004479826BXL8T1YK32V` | the `herzlichkeit-zero.click` zone |
| `CertificateArn` | `…certificate/daae2cd6-…` | ISSUED; expires 2027-05-20, and ACM renews it while the validation CNAME stays |
| `CloudFrontPrefixListId` | `pl-3b927c52` | |
| `VpcId`, `SubnetId`, `AvailabilityZone` | default VPC, us-east-1a | t4g.small is not offered in us-east-1e; a Rule blocks it |
| `ImageId` | `/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64` | latest AMI; used only while `PinnedImageId` is empty |
| `PinnedImageId` | empty | leave empty on create; on every update pass the `ImageIdInUse` output |
| `AttachDataVolume` | `true` | `false` only for step 1 of an AMI upgrade |
| `AppRef` | `main` | branch or tag to build |
| `CertbotEmail` | `roy.herzlichkeit@gmail.com` | Let's Encrypt expiry mail |

## Before the first deploy

1. **Apply the phase 1b boundary.** Run `bash .agent/aws/phase1b/apply-phase1b.sh`.
   It allows certbot to write `_acme-challenge.shortened.herzlichkeit-zero.click`.
   Without it, certbot fails, the app has no certificate, and CloudFront
   returns 502.
2. **Delete the old empty stack.** The failed first attempt left the stack
   `shortened` in `ROLLBACK_COMPLETE` with termination protection on. It has
   no resources. Turn termination protection off, then delete it
   (`UpdateTerminationProtection` false, `DeleteStack`).
3. **Create the SSM parameters** under `/shortened/`. The parameter name, minus
   the path, becomes the environment variable name. Never put the values in a
   file or a commit.

   | Parameter | Type |
   | --- | --- |
   | `/shortened/B2_KEY_ID` | SecureString |
   | `/shortened/B2_APP_KEY` | SecureString |
   | `/shortened/B2_ENDPOINT` | String |
   | `/shortened/B2_REGION` | String |
   | `/shortened/B2_BUCKET` | String |
   | `/shortened/QUOTA_MB`, `/shortened/MAX_USERS` | String, optional |

   Use the default `aws/ssm` key. Its key policy already lets the instance
   decrypt through SSM. Don't set `PORT`, `DB_PATH`, `TLS_*`, `COOKIE_SECURE`
   or `TRUST_PROXY` here: the service sets them.
4. **Activate the `Project` cost allocation tag** in Billing, so the $5 budget
   (Prompt 7) can filter on it.

## Deploy

Use a change set, so you see the full list of changes before anything is
created:

1. `CreateChangeSet`: stack name `shortened`, `ChangeSetType=CREATE`, the body
   of `shortened.yaml` (over 51,200 bytes needs `TemplateURL`; this file is
   about 14 KB), `Capabilities=[CAPABILITY_NAMED_IAM]` (the role and profile
   have fixed names), and `Tags=[{Key=Project,Value=shortened}]`. Stack tags reach every resource that
   supports tags. DNS records, attachments and associations can't take tags.
2. `DescribeChangeSet`: review it.
3. `ExecuteChangeSet`. Creating the CloudFront distribution takes 5–15 minutes.
4. Turn on termination protection for the stack.
5. Check:
   - the stack outputs `SiteUrl`, `DistributionDomain`, `InstanceId`, `ElasticIP` and `DataVolumeId`;
   - the end of `/var/log/shortened-bootstrap.log` (through Session Manager) says `bootstrap done`;
   - `systemctl status shortened`;
   - `https://shortened.herzlichkeit-zero.click/` loads, and you can sign up and upload.

## Update

Use the same flow: `CreateChangeSet` with `ChangeSetType=UPDATE`, review,
then execute.

- **New app version.** UserData runs only at first boot, so changing `AppRef`
  alone does not rebuild the app. On the instance, through Session Manager:
  `cd /opt/shortened-src && git fetch --depth 1 origin <ref> && git checkout FETCH_HEAD && docker build -t shortened . && systemctl restart shortened`.
- **Always pass `PinnedImageId`.** `ImageId` is an SSM parameter, so every
  update resolves it again. Once Amazon publishes a new AL2023 AMI (every few
  weeks), an update without a pinned image replaces the server. So on every
  update, set `PinnedImageId` to the stack's `ImageIdInUse` output. In the
  change set, `Server` must not show `Replacement: True`. If it does, delete
  the change set and check the parameters.
- **OS patches without a new AMI.** Through Session Manager:
  `dnf upgrade --releasever=latest -y && reboot`. `/data` and the app come back
  by themselves (fstab entry and `shortened.service`). This is the normal way
  to stay patched.
- **Moving to a new AMI** takes two updates and a few minutes of downtime.
  Doing it in one update would fail: CloudFormation creates the new server
  first, and the data volume can't attach to it while the old one still holds
  it. The stack would roll back, with the data safe, but nothing would change.
  1. Through Session Manager: `systemctl stop shortened && umount /data`.
     Then update the stack with `AttachDataVolume=false` and the same
     `PinnedImageId`. CloudFormation detaches the volume.
  2. Update with `AttachDataVolume=true` and `PinnedImageId` set to the new AMI
     ID, or empty for the latest. CloudFormation then:
     - creates the new server and attaches the volume to it;
     - moves the Elastic IP;
     - terminates the old server.

     The new server's first boot reuses the volume (`mkfs` runs only on a
     blank disk), rebuilds the image and gets a new Let's Encrypt
     certificate. Allow about 10 minutes.
  3. Note the new `ImageIdInUse` output for later updates.

## Backups (`backup.yaml`)

A second stack, `shortened-backup`, deployed after the main one. Use the same
change-set flow, with `CAPABILITY_NAMED_IAM` and the tag `Project=shortened`.

| Resource | Notes |
| --- | --- |
| `SqliteCopy` (SSM association `shortened-sqlite-backup`) | 02:30 UTC every night, and once right after create. As uid 10001 it runs `sqlite3 .backup` of `/data/shortened.db` to `/data/backup/shortened.db` (through a temp file), then `PRAGMA integrity_check`. The run fails unless the check says `ok`. The DB is in WAL mode, so the live file is never copied as is. |
| `Vault` (`shortened-vault`) | Kept on stack delete (`Retain`). |
| `Plan` (`shortened-daily`) | 03:00 UTC daily, a 60-minute start window, recovery points deleted after `RetentionDays` (7). |
| `Selection` | Only the data volume, by its ID (`DataVolumeId`). |
| `BackupRole` (`shortened-backup-role`) | `AWSBackupServiceRolePolicyForBackup` and `...ForRestores`, with the `shortened-boundary` boundary. |

Parameters: `DataVolumeId` and `InstanceId` default to the main stack's
current outputs. After an AMI upgrade the instance ID changes, so update
`InstanceId` too.

Check the copy: State Manager → Associations → `shortened-sqlite-backup` →
Execution history. The output ends `backup ok …: N bytes, M users`.

### Restore

Every recovery point holds the whole data volume, including last night's clean
copy at `backup/shortened.db`. Use that copy, not the `shortened.db` next to
it, which may have been caught mid-write.

1. **Make a volume.** AWS Backup → `shortened-vault` → pick a recovery point →
   Restore. Choose `us-east-1a`, gp3, encrypted, and the role
   `shortened-backup-role`. Or call `StartRestoreJob` with
   `Metadata={"availabilityZone":"us-east-1a","volumeType":"gp3","encrypted":"true"}`.
2. **Read it on a spare instance.** This is the safe way to check it. Launch a
   t4g.nano in `us-east-1a` with the profile `shortened-instance-profile`, no key
   pair and a security group with no inbound rules. Attach the volume as
   `/dev/sdf`. Then, through Session Manager:
   ```
   dnf install -y sqlite
   mkdir -p /mnt/r && mount -o ro,norecovery /dev/nvme1n1 /mnt/r
   sqlite3 'file:/mnt/r/backup/shortened.db?immutable=1' 'PRAGMA integrity_check; SELECT count(*) FROM users;'
   ```
   `norecovery` and `immutable=1` keep everything read-only.
3. **Put it back into service.** Copy the file, not the volume:
   1. On the server, run `systemctl stop shortened` and set aside the old DB with
      `mv /data/shortened.db{,.old}; rm -f /data/shortened.db-wal /data/shortened.db-shm`.
   2. Copy `backup/shortened.db` to `/data/shortened.db` with owner `10001:10001`,
      mode `0644`. Move it through the spare instance's volume or S3.
   3. Run `systemctl start shortened`.

   Uploads after the backup stay in B2 but are not in the restored database.
   They don't show in the file list and don't count toward the quota.
4. **Clean up.** Detach and delete the restored volume, then terminate the
   spare instance.

## Monitoring (`monitoring.yaml`)

A third stack, `shortened-monitoring`. First update the main stack, so its
instance role has `CloudWatchAgentServerPolicy` (the role is updated in place;
`Server` must not show a replacement). Then create this stack with the
`AlertEmail` parameter, and confirm the SNS subscription mail.

| Resource | Notes |
| --- | --- |
| `Alerts` (SNS `shortened-alerts`) | Mails `AlertEmail` for every alarm and every return to OK. |
| `shortened-system-check` | `StatusCheckFailed_System` ≥ 1 for 2 minutes → the EC2 **recover** action (same instance ID, Elastic IP and volumes) and a mail. |
| `shortened-instance-check` | `StatusCheckFailed_Instance` ≥ 1 for 3 minutes → mail. |
| `shortened-cpu-credits-low` | `CPUCreditBalance` < 50 for 15 minutes → mail. With standard credits, at 0 the CPU is held to the baseline. |
| `shortened-cloudfront-5xx` | `5xxErrorRate` > 10 % in 2 of 3 five-minute periods → mail. No traffic counts as OK. |
| `AppLogGroup` `/shortened/app` | 14-day retention. One stream per instance ID. |
| `AgentConfig` (SSM `AmazonCloudWatch-shortened`) | CloudWatch agent: `mem_used_percent`, and disk `used_percent` on `/` and `/data` (namespace `CWAgent`, every 5 min), plus `/var/log/shortened/app.log`. |
| `AgentSetup` (association `shortened-cloudwatch-agent`) | Installs the agent and logrotate, adds `shortened-journal-export.service` (copies the `shortened.service` journal to the log file, rotated daily) and starts the agent with the config. Runs once on create. |
| `Budget` `shortened-monthly` | $10/month on costs tagged `Project=shortened`. Mails at 80 % actual and 100 % forecast. It reads $0 until the `Project` cost allocation tag is active. `CreateBudget=false` skips it. |

After an AMI upgrade, update `InstanceId` in this stack and in
`shortened-backup`.

## Delete

`DeleteStack` (turn termination protection off first). Ask first: this
removes the instance, its root disk and the Elastic IP.

| Survives a delete | Gone |
| --- | --- |
| **Snapshot of the data volume** (accounts, sessions, quota ledger). `DeletionPolicy: Snapshot`; about 8 GB at most, ≤ $0.40/month until you delete it. | Instance and root disk |
| B2 bucket and all shared files | Elastic IP (released; the address is not kept) |
| ACM certificate and its validation CNAME | Security group, role, instance profile |
| SSM parameters `/shortened/*` | CloudFront distribution |
| Hosted zones and every record the stack didn't create | `shortened` A and AAAA records |
| `shortened-boundary` policy | the data volume itself (after the snapshot) |

To restore, create a volume from the snapshot in the same AZ. Then deploy
with the template changed to use that volume, or copy
`/data/shortened.db` from it.

## Cost (us-east-1, from the Price List API on 2026-11-01)

Running 24/7 (730 h), prices before tax:

| Item | Until 2026-12-31 (t4g.small trial) | From 2027 |
| --- | --- | --- |
| t4g.small, 730 h, standard credits | $0.00 | $12.26 |
| 8 GiB gp3 root | $0.64 | $0.64 |
| 8 GiB gp3 data | $0.64 | $0.64 |
| Public IPv4 (EIP), 730 h | $3.65 | $3.65 |
| Route 53, 2 hosted zones (already exist) | $1.00 | $1.00 |
| Snapshots, up to 8 GB | ≤ $0.40 | ≤ $0.40 |
| AWS Backup, 7 daily EBS recovery points (incremental; only used blocks) | ≈ $0.05 | ≈ $0.05 |
| CloudWatch: 3 agent metrics, 4 alarms, the logs (inside the free tier: 10 metrics, 10 alarms, 5 GB logs) | $0.00 | $0.00 |
| CloudFront (under the free 1 TB and 10 M requests) | $0.00 | $0.00 |
| **Total** | **≈ $6.38** | **≈ $18.64** |

Unit prices: t4g.small $0.0168/h, gp3 $0.08/GB-month, snapshot $0.05/GB-month,
IPv4 $0.005/h, hosted zone $0.50/month.

**The $5/month budget will be exceeded.** Excluding the hosted zones, which
cost the same with or without this stack, the stack itself costs about $5.33
until 2026-12-31 and about $17.59 from 2027. Expect budget alerts every
month unless the limit goes up.

Not included:
- the Cutie volume (≈ $1.60/month);
- App Runner charges;
- the yearly `.click` renewal;
- DNS query charges, which are negligible (alias queries to CloudFront are free).
