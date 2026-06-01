#!/bin/bash
cd /home/kali/AutoRed
source venv/bin/activate
export $(cat .env | xargs)
python3 -m gui.main_window
