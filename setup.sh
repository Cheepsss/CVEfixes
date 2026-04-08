cd Data
git clone https://github.com/olbat/nvdcve
cd ..
sudo apt install python3.9 python3.9-venv python3.9-dev build-essential
python3.9 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

