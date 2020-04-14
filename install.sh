if [ "$(id -u)" != "0" ]; then
  echo '[Error]: You must run this setup script with root privileges.'
  echo
  exit 1
fi
apt-get install python3-pip
apt-get install mono-complete
pip3 install -e .
