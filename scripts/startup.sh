#!/bin/bash
sleep 90
set -xe
set -o pipefail

# Only run the script once
if [ -f ~/.startup-script-complete ]; then
  echo "Startup script already ran, exiting"
  exit 0
fi

# Data
LOCAL_IP="$(curl -sf -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/network-interfaces/0/ip)"


# Deps
export DEBIAN_FRONTEND=noninteractive
echo "set to non interactive mode installing update"
apt-get update
echo "installing  google-cloud-sdk=272.0.0-0"
apt-get install -y --allow-downgrades google-cloud-sdk=272.0.0-0
echo "installing -y libsasl2-2 libsasl2-modules-db libssl1.0.2 --upgrade"
apt-get install -y libsasl2-2 libsasl2-modules-db libssl1.0.2
echo "installing libcap2-bin logrotate netcat nginx unzip"
apt-get install -y jq libcap2-bin logrotate netcat nginx unzip
echo "installing build-essential"
apt-get install -y build-essential
echo "installing libreadline-gplv2-dev"
apt-get install -y libreadline-gplv2-dev
echo "installing libncursesw5-dev"
apt-get install -y libncursesw5-dev
echo "installing libssl-dev"
apt-get install -y libssl-dev
echo "installing libsqlite3-dev"
apt-get install -y libsqlite3-dev
echo "installing tk-dev"
apt-get install -y tk-dev
echo "installing libgdbm-dev"
apt-get install -y libgdbm-dev
echo "installing libc6-dev"
apt-get install -y libc6-dev
echo "installing libbz2-dev"
apt-get install -y libbz2-dev
echo "installing libffi-dev"
apt-get install -y libffi-dev
echo "installing python3-dev"
apt-get install -y python3-dev
echo "installing python3-pip"
apt-get install -y python3-pip
echo "installing rsync"
apt-get install -y rsync
echo "installing python-pip"
apt-get install -y python-pip
echo "installing software-properties-common"
apt-get install -y software-properties-common
echo "installing zlib1g-dev"
apt-get install -y zlib1g-dev
echo "installing libncurses5-dev"
apt-get install -y libncurses5-dev
echo "installing libnss3-dev"
apt-get install -y libnss3-dev
echo "installing libssl-dev"
apt-get install -y libssl-dev
echo "installing libreadline-dev"
apt-get install -y libreadline-dev
echo "installing libffi-dev wget"
apt-get install -y libffi-dev wget
echo "installing git"
apt-get install -y git
pip3 install --upgrade pip
cd /usr/src
curl -O https://www.python.org/ftp/python/3.7.3/Python-3.7.3.tar.xz
tar -xf Python-3.7.3.tar.xz
cd Python-3.7.3
./configure
make -j 2
make install
PATH=$PATH:~/.local/bin/
source ~/.bashrc
cd /usr/bin
ln -sfn /usr/local/bin/python3.7 python
cd /usr/src/

export GOOGLE_APPLICATION_CREDENTIALS=$HOME/secrets/vault-kms-read-write.json
export VAULT_ADDR="https://35.245.181.128:443"
export VAULT_TOKEN="s.clSkq5XCMvt0glR0OpkdjoFT"
export VAULT_CAPATH=$HOME/secrets/ca.pem
export VAULT_FORMAT="json"
export project_id="vault-f59e6f7462611dc1"
export location_id="us-east4"
export key_ring_id="vault-2aeb527abb5ec837"
export crypto_key_id="kubernetes-secrets"

pip3 install --user virtualenvwrapper
mkdir ~/Envs
echo 'export WORKON_HOME=~/Envs' >> ~/.bashrc
echo 'source ~/.local/bin/virtualenvwrapper.sh' >> ~/.bashrc
source ~/.bashrc


eval 'set +o history' 2>/dev/null || setopt HIST_IGNORE_SPACE 2>/dev/null
 touch ~/.gitcookies
 chmod 0600 ~/.gitcookies

 git config --global http.cookiefile ~/.gitcookies

 tr , \\t <<\__END__ >>~/.gitcookies
source.developers.google.com,FALSE,/,TRUE,2147483647,o,git-Darthvenom69.gmail.com=1//0fq4IZ-8AadXLCgYIARAAGA8SNwF-L9Iro5supt5PuLzU6AMddUzehchzPnTRIRmUZFmOo7_X3m0VaMbyhdcPeniJoQwIpC09kIk
__END__
eval 'set -o history' 2>/dev/null || unsetopt HIST_IGNORE_SPACE 2>/dev/null

git clone https://source.developers.google.com/p/kryptoknight-259909/r/github_devinasj_kryptoknight


cd github_devinasj_kryptoknight
pip3 install -r ./requirements.txt

mkdir $HOME/secrets/
cp ./vault-kms-read-write.json $HOME/secrets/vault-kms-read-write.json
cp ./ca.pem $HOME/secrets/ca.pem

# Install Stackdriver for logging and monitoring
curl -sSfL https://dl.google.com/cloudagents/install-logging-agent.sh | bash
curl -sSfL https://dl.google.com/cloudagents/install-monitoring-agent.sh | bash

# Download and install Vault
cd /tmp && \
  curl -sLfO "https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_linux_amd64.zip" && \
  unzip "vault_${vault_version}_linux_amd64.zip" && \
  mv vault /usr/local/bin/vault && \
  rm "vault_${vault_version}_linux_amd64.zip"

# Give Vault the ability to run mlock as non-root
/sbin/setcap cap_ipc_lock=+ep /usr/local/bin/vault

## Add Vault user
#useradd -d /etc/vault.d -s /bin/false vault
#
## Vault config
#mkdir -p /etc/vault.d
#cat <<"EOF" > /etc/vault.d/config.hcl
#${config}
#EOF
#chmod 0600 /etc/vault.d/config.hcl
#
## Sub in local IP
## $$ is correct here because we are in terraform template
#sed -i "s/LOCAL_IP/$${LOCAL_IP}/g" /etc/vault.d/config.hcl
#
## Service environment
#cat <<"EOF" > /etc/vault.d/vault.env
#VAULT_ARGS=${vault_args}
#EOF
#chmod 0600 /etc/vault.d/vault.env
#
## Download TLS files from GCS
#mkdir -p /etc/vault.d/tls
#gsutil cp "gs://${vault_tls_bucket}/${vault_ca_cert_filename}" /etc/vault.d/tls/ca.crt
#gsutil cp "gs://${vault_tls_bucket}/${vault_tls_cert_filename}" /etc/vault.d/tls/vault.crt
#gsutil cp "gs://${vault_tls_bucket}/${vault_tls_key_filename}" /etc/vault.d/tls/vault.key.enc
#
## Decrypt the Vault private key
#base64 --decode < /etc/vault.d/tls/vault.key.enc | gcloud kms decrypt \
#  --project="${kms_project}" \
#  --location="${kms_location}" \
#  --keyring="${kms_keyring}" \
#  --key="${kms_crypto_key}" \
#  --plaintext-file=/etc/vault.d/tls/vault.key \
#  --ciphertext-file=-
#
## Make sure Vault owns everything
#chmod 700 /etc/vault.d/tls
#chmod 600 /etc/vault.d/tls/vault.key
#chown -R vault:vault /etc/vault.d
#rm /etc/vault.d/tls/vault.key.enc
#
## Make audit files
#mkdir -p /var/log/vault
#touch /var/log/vault/{audit,server}.log
#chmod 0640 /var/log/vault/{audit,server}.log
#chown -R vault:adm /var/log/vault
#
## Systemd service
#cat <<"EOF" > /etc/systemd/system/vault.service
#[Unit]
#Description="HashiCorp Vault"
#Documentation=https://www.vaultproject.io/docs/
#Requires=network-online.target
#After=network-online.target
#ConditionFileNotEmpty=/etc/vault.d/config.hcl
#
#[Service]
#User=vault
#Group=vault
#ProtectSystem=full
#ProtectHome=read-only
#PrivateTmp=yes
#PrivateDevices=yes
#SecureBits=keep-caps
#StandardError=syslog
#StandardOutput=syslog
#SyslogIdentifier=vault
#AmbientCapabilities=CAP_IPC_LOCK
#CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
#NoNewPrivileges=yes
#EnvironmentFile=/etc/vault.d/vault.env
#ExecStart=/usr/local/bin/vault server -config=/etc/vault.d/config.hcl $VAULT_ARGS
#ExecReload=/bin/kill --signal HUP $MAINPID
#KillMode=process
#KillSignal=SIGINT
#Restart=on-failure
#RestartSec=5
#TimeoutStopSec=30
#
#[Install]
#WantedBy=multi-user.target
#EOF
#chmod 0644 /etc/systemd/system/vault.service
#systemctl daemon-reload
#systemctl enable vault
#
## Prevent core dumps - from all attack vectors
#cat <<"EOF" > /etc/sysctl.d/50-coredump.conf
#kernel.core_pattern=|/bin/false
#EOF
#sysctl -p /etc/sysctl.d/50-coredump.conf
#
#cat <<"EOF" > /etc/security/limits.conf
#* hard core 0
#EOF
#
#mkdir -p /etc/systemd/coredump.conf.d
#cat <<"EOF" > /etc/systemd/coredump.conf.d/disable.conf
#[Coredump]
#Storage=none
#EOF
#
#cat <<"EOF" >> /etc/sysctl.conf
#fs.suid_dumpable = 0
#EOF
#sysctl -p
#
#cat <<"EOF" > /etc/profile.d/ulimit.sh
#ulimit -S -c 0 > /dev/null  2>&1
#EOF
#source /etc/profile.d/ulimit.sh
#
## Reload any systemd changes for core dumps
#systemctl daemon-reload
#
## Setup vault env
#cat <<"EOF" > /etc/profile.d/vault.sh
#export VAULT_ADDR="http://127.0.0.1:${vault_port}"
#
## Ignore history from any Vault commands
#export HISTIGNORE="&:vault*"
#EOF
#chmod 644 /etc/profile.d/vault.sh
#source /etc/profile.d/vault.sh
#
## Add health-check proxy because target pools don't support HTTPS
#cat <<EOF > /etc/nginx/sites-available/default
#server {
#  listen ${vault_proxy_port};
#  location / {
#    proxy_pass $VAULT_ADDR/v1/sys/health?uninitcode=200;
#  }
#}
#EOF
#systemctl enable nginx
#systemctl restart nginx
#
## Pull Vault data from syslog into a file for fluentd
#cat <<"EOF" > /etc/rsyslog.d/vault.conf
##
## Extract Vault logs from syslog
##
#
## Only include the message (Vault has its own timestamps and data)
#template(name="OnlyMsg" type="string" string="%msg:2:$:drop-last-lf%\n")
#
#if ( $programname == "vault" ) then {
#  action(type="omfile" file="/var/log/vault/server.log" template="OnlyMsg")
#  stop
#}
#EOF
#systemctl restart rsyslog
#
## Start Stackdriver logging agent and setup the filesystem to be ready to
## receive audit logs
#cat <<"EOF" > /etc/google-fluentd/config.d/vaultproject.io.conf
#<source>
#  @type tail
#  format json
#
#  time_type "string"
#  time_format "%Y-%m-%dT%H:%M:%S.%N%z"
#  keep_time_key true
#
#  path /var/log/vault/audit.log
#  pos_file /var/lib/google-fluentd/pos/vault.audit.pos
#  read_from_head true
#  tag vaultproject.io/audit
#</source>
#
#<filter vaultproject.io/audit>
#  @type record_transformer
#  enable_ruby true
#  <record>
#    message "$${record.dig('request', 'id') || '-'} $${record.dig('request', 'remote_address') || '-'} $${record.dig('auth', 'display_name') || '-'} $${record.dig('request', 'operation') || '-'} $${record.dig('request', 'path') || '-'}"
#    host "#{Socket.gethostname}"
#  </record>
#</filter>
#
#<source>
#  @type tail
#  format /^(?<time>[^ ]+) \[(?<severity>[^ ]+)\][ ]+(?<source>[^:]+): (?<message>.*)/
#
#  time_type "string"
#  time_format "%Y-%m-%dT%H:%M:%S.%N%z"
#  keep_time_key true
#
#  path /var/log/vault/server.log
#  pos_file /var/lib/google-fluentd/pos/vault.server.pos
#  read_from_head true
#  tag vaultproject.io/server
#</source>
#
#<filter vaultproject.io/server>
#  @type record_transformer
#  enable_ruby true
#  <record>
#    message "$${record['source']}: $${record['message']}"
#    severity "$${(record['severity'] || '').downcase}"
#    host "#{Socket.gethostname}"
#  </record>
#</filter>
#EOF
#systemctl enable google-fluentd
#systemctl restart google-fluentd
#
## Configure logrotate for Vault audit logs
#cat <<"EOF" > /etc/logrotate.d/vaultproject.io
#/var/log/vault/*.log {
#  daily
#  rotate 3
#  missingok
#  compress
#  notifempty
#  create 0640 vault adm
#  sharedscripts
#  postrotate
#    test -s run/rsyslogd.pid && kill -HUP $(cat /run/rsyslogd.pid)
#    true
#  endscript
#}
#EOF
#
## Start Stackdriver monitoring
#curl -sSfLo /opt/stackdriver/collectd/etc/collectd.d/statsd.conf https://raw.githubusercontent.com/Stackdriver/stackdriver-agent-service-configs/master/etc/collectd.d/statsd.conf
#systemctl enable stackdriver-agent
#systemctl restart stackdriver-agent
#
## Signal this script has run
#touch ~/.startup-script-complete

# Reboot to pick up system-level changes
sudo reboot
