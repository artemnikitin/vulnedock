# vulnedock
Proof of concept for vulnerability management of Docker containers

### Description
This is the proof of concept inspired by [this post](https://avleonov.com/2017/05/03/my-comments-on-forresters-vulnerability-management-vendor-landscape-2017/)    
The tool scans all containers that currently runs on the host and checks info about known vulnerabilities on [vulners.com](https://vulners.com/)

### Current limitations
- vulners.com doesn't support Alpine
