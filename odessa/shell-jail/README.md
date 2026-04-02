# ~~h0rnyj4il~~ Shell Jail
## Abstract
~~h0rnyj4il~~ This shell jail is a docker based userjail based on jail challenges one would find in CTFs. The difference here is there is no flag, and you are not meant to be able to escape. The main usecase for this tool is to trap incoming ssh connections specifically in a red/blue competitive setting. There may be escapes, however I do not currently set up the container in an escapable way.
## Deploying
```bash
sudo ./jail.sh <user>
```
## Dependencies
- Linux
- Docker installed
- Sudo access
