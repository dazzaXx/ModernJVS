# DietPi Automation Setup
The 2 files here are to setup the Pi with ModernJVS without any user interaction.

Once you've written DietPi to your SD card, open up the partition you can see with a bunch of files and copy both of these files over to it. It will ask to replace 1 of them, press yes.

Note: Don't forget to setup your internet beforehand, the dietpi.txt here is set to automatically connect via WiFi and it reads the wifi login info from **dietpi-wifi.txt** so make sure it is set there or **AUTO_SETUP_NET_WIFI_ENABLED** in **dietpi.txt** is set to 0 if you're using an ethernet connection.

Note 2: Make sure to change **AUTO_SETUP_GLOBAL_PASSWORD** to whatever you want it to be, as that will become your login password for root and the dietpi user.
