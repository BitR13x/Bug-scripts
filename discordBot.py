#!/bin/python
import discord
import os
from sys import argv
from datetime import datetime
import json

if len(argv) < 2:
    print("python <program> <domain> <foldername>")
    raise IndexError("You are missing argument")

with open("discord.json", "r") as f:
    data = json.load(f)

    TOKEN = data["token"]
    user_id = data["user_id"]
    f.close()

intents = discord.Intents.default()
client = discord.Client(intents=intents)

async def Exists_send(filepath):
    if (os.path.exists(os.path.join(os.getcwd(), filepath))):
        await user.send(file=discord.File(filepath))
    else:
        await user.send(f"I'm missing: {filepath}")

@client.event
async def on_ready():
    print(f'{client.user} has connected to Discord!')
    global user
    user = await client.fetch_user(user_id)


    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    await user.send(f"Finished scanning for {argv[1]} IN {current_time}")

    root = argv[1] + "/" + argv[2] + "/"
    wayback = root + "wayback/"
    for extension in ["js.txt","jsp.txt","json.txt","php.txt","aspx.txt","ts.txt","md.txt","yaml.txt","xml.txt"]:
        await Exists_send(wayback+"extensions/"+extension)
    
    await Exists_send(wayback+"wayback_output.txt")
    await Exists_send(wayback+"wayback_params.txt")
    await Exists_send(root + "html_report.html")   

    await client.close()


client.run(TOKEN)