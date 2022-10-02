# Development Notes

```
# install trivy
https://aquasecurity.github.io/trivy/v0.18.3/installation/

# install nats-server
curl -LO https://github.com/nats-io/nats-server/releases/download/v2.9.2/nats-server-v2.9.2-linux-amd64.tar.gz
tar -xzvf nats-server-v2.9.2-linux-amd64.tar.gz
mv nats-server-v2.9.2-linux-amd64/nats-server /usr/local/bin/

# upload systemd unit files
scp hack/systemd/nats-server.service root@this-is-nats.appscode.ninja:/lib/systemd/system/nats-server.service
scp hack/systemd/scanner-backend.service root@this-is-nats.appscode.ninja:/lib/systemd/system/scanner-backend.service

# ssh into remote server
$ ssh root@this-is-nats.appscode.ninja
$ systemctl enable nats-server.service
$ systemctl enable scanner-backend.service
```

```bash
# on development machine
make build OS=linux ARCH=amd64
scp bin/scanner-linux-amd64 root@this-is-nats.appscode.ninja:/root


# on production server
> ssh root@this-is-nats.appscode.ninja

chmod +x scanner-linux-amd64
mv scanner-linux-amd64 /usr/local/bin/scanner
sudo systemctl restart scanner-backend
```

```
# generate report
nats -s this-is-nats.appscode.ninja \
  --user=$NATS_USERNAME \
  --password=$NATS_PASSWORD \
  publish scanner.queue.generate centos

# read scanner report
nats -s this-is-nats.appscode.ninja \
  --user=$NATS_USERNAME \
  --password=$NATS_PASSWORD \
  request scanner.report centos

# read scanner summary
nats -s this-is-nats.appscode.ninja \
  --user=$NATS_USERNAME \
  --password=$NATS_PASSWORD \
  request scanner.summary centos
```
