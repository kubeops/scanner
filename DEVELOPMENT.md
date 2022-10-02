# Development Notes

```
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
sudo systemctl restart scanner
```
