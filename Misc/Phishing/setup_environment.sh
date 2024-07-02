#!/bin/bash

# Update package list
sudo apt update

# Install Python3 and pip
sudo apt install -y python3 python3-pip

# Install Flask using pip
pip3 install flask

# Install ngrok
sudo apt-get install -y ngrok

# Install npm
sudo apt-get install -y npm

# Install serve globally using npm
sudo npm install -g serve

echo "Environment setup complete."
