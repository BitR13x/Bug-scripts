# Bug-scripts

My personal scripts that I use for penetration testing.


<!--
```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/cgboal/sonarsearch/cmd/crobat@latest
```
 -->

## Status

bug-recon is not tested and in development
ctf-recon is in development (exploit suggester does not work)

## Discord notification

`discordBot.py` python script for sending files.

Config `discord.json`:

```json
{
    "token": string,
    "user_id": string
}
```