#!/bin/bash

sudo python3 setup.py build
sudo python3 setup.py install
sudo service walinuxagent restart

